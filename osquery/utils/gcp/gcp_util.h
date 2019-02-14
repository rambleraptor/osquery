namespace osquery {
  const std::string GCE_METADATA_ENDPOINT = "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true";

  static bool isGceInstance();

  Status getGceMetadata();

  class GceResponse {
    void set_response(std::stringstream *json_stream);

    std::string get(std::string key);
  }
}
