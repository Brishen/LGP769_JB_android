Background
===========
1.) A2dpAudioInterface has been moved/renamed to external/bluetooth/bluez/android_audio_hw.c
2.) BlueZ's liba2dp shall now include android_audio_hw.c and liba2dp.c. Similar to GB, liba2dp.c is the entry point into the BlueZ A2DP stack.  
3.) The new liba2dp shall be linked with AudioFlinger library
4.) The new liba2dp shall be loaded by Audioflinger using the HAL abstraction
5.) In order for AudioFlinger to automatically load this module using HAL, it has to be named as 'a2dp.audio.default.so'
6.) The android_audio_hw.c implements the needed HAL layer and is the interface between AudioFlinger and BlueZ's liba2dp.c
7.) The android_audio_hw.c continues to invoke the same a2dp_XXX functions

BTLA approach - Enhancements/Modifications
============================================
1.) A new folder 'a2dp_audio_hw' has been created in mydroid/hardware/broadcom/bt/adaptation
2.) The android_audio_hw.c has been re-used for BTLA as well. We have made a copy of this as this is expected to be implemented per Audio Hardware.
3.) A new implementation 'liba2dp_brcm.c' has been created which implements the a2dp_XXX functions. This file shall perform the socket functions that talk to BTLD's A2DP stack.
4.) The new library shall be called 'a2dp.audio.default.so' as this is needed by AudioFlinger.

