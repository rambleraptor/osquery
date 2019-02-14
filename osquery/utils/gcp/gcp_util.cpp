#include <osquery/utils/gcp/gcp_util.h>
#include <osquery/remote/http_client.h>
// Checks if an instance is a GCE instance by attempting to make a connection
// to the GCE metadata server
static bool isGceInstance() {
  static std::atomic<bool> checked(false);
  static std::atomic<bool> is_gce_instance(false):

  if(checked) {
    return is_gce_instance;
  }

  pt::ptree tree;

  Status gceStatus = getGceMetadata(tree);

  checked = true;
  is_gce_instance = s.ok();
  return is_gce_instance;
}

// Get the metadata from GCE and return a status + tree of responses.
Status getGceMetadata(pt::ptree& response_hash) {
  http::Request request(GCE_METADATA_SERVER);

  http::Client::Options opts;
  http::Response response;

  http::Client client(opts);

  request << http::Request::Header("Metadata-Flavor", "Google");
  request << http::Request::Header("User-Agent", "OSQuery");

  // Send the request
  try {
    response = client.get(request);
  } catch (const std::system_error& e) {
    return Status(
        1, "OSQuery GCE Request failed:" + e.what());
  }

  // Error check response
  if (response.result_int() != 200) {
    return Status(1,
                  "Bad GCE metadata response " +
                   std::to_string(response.result_int()));
  }

  // Build tree from response
  std::stringstream json_stream;
  json_stream << response.body();
  try {
    pt::read_json(json_stream, response_hash);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1,
                  "Couldn't parse JSON from GCE metadata: " + e.what());
  }

   return Status(0);

}
