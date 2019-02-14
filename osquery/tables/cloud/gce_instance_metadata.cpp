i/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/utils/gce/gce_util.h>

namespace osquery {
namespace tables {

QueryData getGceMetadata(QueryContext& context) {
  QueryData results;
  Row r;

  if(!isGceInstance()){
    return results;
  }

  // Set properties.
  GceResponse response;
  getGceMetadata(response);
  
  r["id"] = response.get("id");
  r["cpu_platform"] = response.get("cpuPlatform");
  r["description"] = response.get("description");
  r["hostname"] = response.get("hostname");
  r["machine_type"] = response.get("machineType");
  r["image"] = response.get("image");
  r["name"] = response.get("name");
  r["preempted"] = response.get("preempted");
  r["zone"] = response.get("zone");

  results.push_back(r);
  return results;
}
}
}
