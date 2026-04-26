#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <android/log.h>

#include <elfio/elfio.hpp>
#include <And64InlineHook.hpp>
#include <zygisk_next_api.h>

#define LOG_TAG "A64HookDrmModule"
#define LOGD(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static std::string g_extra_data;

struct HookInstance {
	void (*bak_Update)(void*, const void*, size_t) = nullptr;
	void (*bak_Final)(unsigned char*, void*) = nullptr;
};

static std::vector<HookInstance*> g_instances;

[[gnu::naked]] static void trampoline_Update_template() {
	// x0=ctx, x1=data, x2=len on entry; inject instance_ptr into x3.
	asm volatile (
		"bti jc\n"
		"ldr x3, #8\n"
		"b #0xC\n"
		"nop\n"
		"nop\n"
		"ldr x16, #8\n"
		"ret x16\n"
		"nop\n"
		"nop\n"
	);
}

[[gnu::naked]] static void trampoline_Final_template() {
	// x0=hash, x1=ctx on entry; inject instance_ptr into x2.
	asm volatile (
		"bti jc\n"
		"ldr x2, #8\n"
		"b #0xC\n"
		"nop\n"
		"nop\n"
		"ldr x16, #8\n"
		"ret x16\n"
		"nop\n"
		"nop\n"
	);
}

static constexpr size_t TRAMPOLINE_SIZE = 0x24;
static constexpr size_t TRAMPOLINE_INSTANCE_OFF = 0x0C;
static constexpr size_t TRAMPOLINE_HOOK_OFF = 0x1C;

extern "C" void real_SHA256_Update(void *ctx, const void *data, size_t len, uint64_t inst_ptr) {
	auto inst = reinterpret_cast<HookInstance*>(inst_ptr);
	if (inst && inst->bak_Update)
		inst->bak_Update(ctx, data, len);
}

extern "C" void real_SHA256_Final(unsigned char *hash, void *ctx, uint64_t inst_ptr) {
	auto inst = reinterpret_cast<HookInstance*>(inst_ptr);
	if (inst && inst->bak_Update) {
		LOGD("injecting extra_data before SHA256_Final");
		inst->bak_Update(ctx, g_extra_data.data(), g_extra_data.size());
	}
	if (inst && inst->bak_Final)
		inst->bak_Final(hash, ctx);
}

static void *alloc_trampoline() {
	const long page = sysconf(_SC_PAGESIZE);
	void *mem = mmap(nullptr, static_cast<size_t>(page), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		LOGD("mmap RWX failed: trampoline allocation");
		return nullptr;
	}
	return mem;
}

static void *make_trampoline(bool is_update, HookInstance *inst, void *real_hook_fn) {
	void *mem = alloc_trampoline();
	if (!mem)
		return nullptr;

	const void *tmpl = is_update ? reinterpret_cast<const void*>(trampoline_Update_template) : reinterpret_cast<const void*>(trampoline_Final_template);

	auto p = static_cast<uint8_t*>(mem);
	memcpy(p, tmpl, TRAMPOLINE_SIZE);

	*reinterpret_cast<uint64_t*>(p + TRAMPOLINE_INSTANCE_OFF) = reinterpret_cast<uint64_t>(inst);
	*reinterpret_cast<uint64_t*>(p + TRAMPOLINE_HOOK_OFF) = reinterpret_cast<uint64_t>(real_hook_fn);

	__builtin___clear_cache(p, p + TRAMPOLINE_SIZE);
	mprotect(mem, static_cast<size_t>(sysconf(_SC_PAGESIZE)), PROT_READ | PROT_EXEC);
	return mem;
}

struct MapEntry {
	uint64_t base;
	std::string path;
};

static bool parse_maps_line(const std::string& line, MapEntry& out) {
	const char *p = line.c_str();
	const char *end = p + line.size();

	uint64_t base = 0;
	for (; p < end && *p != '-'; ++p) {
		char c = *p;
		if (c >= '0' && c <= '9')
			base = (base << 4) | static_cast<uint64_t>(c - '0');
		else if (c >= 'a' && c <= 'f')
			base = (base << 4) | static_cast<uint64_t>(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			base = (base << 4) | static_cast<uint64_t>(c - 'A' + 10);
		else
			return false;
	}
	if (p >= end || *p != '-')
		return false;

	while (p < end && *p != ' ')
		++p;

	for (int field = 0; field < 3; ++field) {
		while (p < end && *p == ' ')
			++p;
		while (p < end && *p != ' ')
			++p;
	}

	while (p < end && *p == ' ')
		++p;
	while (p < end && *p != ' ')
		++p;
	while (p < end && *p == ' ')
		++p;

	std::string path(p, end);
	while (!path.empty() && (path.back() == ' ' || path.back() == '\n' || path.back() == '\r' || path.back() == '\t'))
		path.pop_back();

	if (path.empty() || path.front() == '[')
		return false;
	if (path.find("(deleted)") != std::string::npos)
		return false;
	if (path.substr(0, 5) == "/dev/")
		return false;

	out.base = base;
	out.path = std::move(path);
	return true;
}

static std::vector<std::string> scan_libcrypto_paths() {
	std::ifstream f("/proc/self/maps");
	if (!f.is_open()) {
		LOGD("cannot open /proc/self/maps");
		return {};
	}

	std::vector<std::string> result;
	std::string line;
	while (std::getline(f, line)) {
		if (line.find("libcrypto.so") == std::string::npos)
			continue;

		MapEntry e;
		if (!parse_maps_line(line, e))
			continue;
		if (e.path.find("libcrypto.so") == std::string::npos)
			continue;

		bool dup = false;
		for (auto& s : result)
			if (s == e.path) { dup = true; break; }
		if (!dup)
			result.push_back(std::move(e.path));
	}
	return result;
}

static uint64_t get_module_base(const std::string& path) {
	std::ifstream f("/proc/self/maps");
	if (!f.is_open()) return 0;

	std::string line;
	while (std::getline(f, line)) {
		if (line.find(path) == std::string::npos)
			continue;

		MapEntry e;
		if (!parse_maps_line(line, e))
			continue;
		if (e.path != path)
			continue;

		const char *p = line.c_str();
		const char *end = p + line.size();
		while (p < end && *p != ' ')
			++p;
		while (p < end && *p == ' ')
			++p;
		while (p < end && *p != ' ')
			++p;
		while (p < end && *p == ' ')
			++p;
		bool zero_offset = true;
		while (p < end && *p != ' ') {
			if (*p != '0') {
				zero_offset = false;
				break;
			}
			++p;
		}
		if (zero_offset)
			return e.base;
	}
	return 0;
}

static void *find_symbol_via_elfio(const std::string& lib_path, uint64_t base_addr, const char *sym_name) {
	ELFIO::elfio reader;
	if (!reader.load(lib_path)) {
		LOGD("ELFIO: cannot load %s", lib_path.c_str());
		return nullptr;
	}

	for (const auto& sec : reader.sections) {
		auto type = sec->get_type();
		if (type != ELFIO::SHT_DYNSYM && type != ELFIO::SHT_SYMTAB)
			continue;

		ELFIO::symbol_section_accessor syms(reader, sec.get());
		const auto count = syms.get_symbols_num();

		for (unsigned i = 0; i < count; ++i) {
			std::string name;
			ELFIO::Elf64_Addr value = 0;
			ELFIO::Elf_Xword size = 0;
			unsigned char bind = 0, type_s = 0, other = 0;
			ELFIO::Elf_Half shndx = 0;

			syms.get_symbol(i, name, value, size, bind, type_s, shndx, other);

			if (name != sym_name)
				continue;
			if (value == 0)
				continue;
			if (type_s != ELFIO::STT_FUNC && type_s != ELFIO::STT_NOTYPE)
				continue;

			void *addr = reinterpret_cast<void*>(base_addr + value);
			LOGD("ELFIO: %s @ %p (base=0x%llx + off=0x%llx) in %s", sym_name, addr, static_cast<unsigned long long>(base_addr), static_cast<unsigned long long>(value), lib_path.c_str());
			return addr;
		}
	}

	LOGD("ELFIO: %s not found in %s", sym_name, lib_path.c_str());
	return nullptr;
}

static std::string make_random_hex(size_t len) {
	static const char charset[] = "0123456789ABCDEF";
	auto seed = static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count());
	std::mt19937 rng(seed);
	std::uniform_int_distribution<int> dist(0, 15);

	std::string out;
	out.reserve(len);
	for (size_t i = 0; i < len; ++i)
		out += charset[dist(rng)];
	return out;
}

void onModuleLoaded(void *self_handle, const struct ZygiskNextAPI *api) {

	g_extra_data = make_random_hex(32);
	LOGD("extra_data initialised (%zu bytes)", g_extra_data.size());

	auto paths = scan_libcrypto_paths();
	if (paths.empty()) {
		LOGD("no libcrypto.so found in /proc/self/maps");
		return;
	}
	LOGD("found %zu libcrypto.so instance(s)", paths.size());

	g_instances.reserve(paths.size());

	for (const auto& path : paths) {
		uint64_t base = get_module_base(path);
		if (base == 0) {
			LOGD("cannot resolve base for %s, skipping", path.c_str());
			continue;
		}
		LOGD("base 0x%llx → %s", static_cast<unsigned long long>(base), path.c_str());

		void *addr_Update = find_symbol_via_elfio(path, base, "SHA256_Update");
		void *addr_Final = find_symbol_via_elfio(path, base, "SHA256_Final");

		if (!addr_Update && !addr_Final) {
			LOGD("neither SHA256_Update nor SHA256_Final found in %s", path.c_str());
			continue;
		}

		auto inst = new HookInstance{};
		bool hooked_any = false;

		if (addr_Update) {
			void *tramp = make_trampoline(true, inst, reinterpret_cast<void*>(real_SHA256_Update));
			if (tramp) {
				A64HookFunction(addr_Update, tramp, reinterpret_cast<void**>(&inst->bak_Update));
				LOGD("A64HookFunction SHA256_Update @ %p in %s", addr_Update, path.c_str());
				hooked_any = true;
			} else {
				LOGD("make_trampoline for SHA256_Update failed, skipping");
			}
		}

		if (addr_Final) {
			void *tramp = make_trampoline(false, inst, reinterpret_cast<void*>(real_SHA256_Final));
			if (tramp) {
				A64HookFunction(addr_Final, tramp, reinterpret_cast<void**>(&inst->bak_Final));
				LOGD("A64HookFunction SHA256_Final @ %p in %s", addr_Final, path.c_str());
				hooked_any = true;
			} else {
				LOGD("make_trampoline for SHA256_Final failed, skipping");
			}
		}

		if (hooked_any) {
			g_instances.push_back(inst);
		} else {
			delete inst;
		}
	}

	LOGD("done hooked %zu libcrypto instance(s)", g_instances.size());
}

__attribute__((visibility("default"), unused)) struct ZygiskNextModule zn_module = {
	.target_api_version = ZYGISK_NEXT_API_VERSION_1,
	.onModuleLoaded = onModuleLoaded
};
