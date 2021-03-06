/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <string>
#include <CoreFoundation/CoreFoundation.h>

namespace osquery {

std::string stringFromCFData(const CFDataRef& cf_data);

}
