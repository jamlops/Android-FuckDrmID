LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := drmid
LOCAL_C_INCLUDES := $(LOCAL_PATH)/
LOCAL_CPPFLAGS := -Oz
LOCAL_SRC_FILES := And64InlineHook.cpp hook.cpp
LOCAL_STATIC_LIBRARIES := libcxx
LOCAL_LDLIBS := -llog -landroid
include $(BUILD_SHARED_LIBRARY)

include $(LOCAL_PATH)/external/libcxx/Android.mk