#
# Copyright 2020-2022 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

FIND_PATH(SACLIENT_INCLUDE_DIR sa.h)

SET(SACLIENT_NAMES ${SACLIENT_NAMES} saclient libsaclient)
FIND_LIBRARY(SACLIENT_LIBRARY NAMES ${SACLIENT_NAMES} PATH)

IF(SACLIENT_INCLUDE_DIR AND SACLIENT_LIBRARY)
    SET(SACLIENT_FOUND TRUE)
ENDIF(SACLIENT_INCLUDE_DIR AND SACLIENT_LIBRARY)

IF(SACLIENT_FOUND)
    IF(NOT SACLIENT_FIND_QUIETLY)
        MESSAGE(STATUS "Found SACLIENT: ${SACLIENT_LIBRARY}")
    ENDIF (NOT SACLIENT_FIND_QUIETLY)
ELSE(SACLIENT_FOUND)
    IF(SACLIENT_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could not find saclient")
    ENDIF(SACLIENT_FIND_REQUIRED)
ENDIF(SACLIENT_FOUND)
