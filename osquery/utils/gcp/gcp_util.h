namespace osquery {
  const std::string GCE_METADATA_ENDPOINT = "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true";

  static bool isGceInstance();

  Status getGceMetadata();
}
