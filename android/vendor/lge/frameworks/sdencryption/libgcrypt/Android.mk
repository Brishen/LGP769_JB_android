# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LIBGCRYPT_BASE_DIR := $(call my-dir)

# Android does not have an PTH port yet, so we explicitly disable random daemon
# here. Please also check USE_RANDOM_DAEMON in config.h and RANDOM_DAEMON_SOCKET
# in random/random-daemon.c.
GCRYPT_USE_RANDOM_DAEMON := false

.PHONY: all-libgcrypt-targets clean-all-libgcrypt-targets
include $(call all-makefiles-under,$(LIBGCRYPT_BASE_DIR))

