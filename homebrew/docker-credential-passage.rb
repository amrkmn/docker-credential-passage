class DockerCredentialPassage < Formula
  desc "Docker credential helper using age encryption"
  homepage "https://github.com/amrkmn/docker-credential-passage"
  url "https://github.com/amrkmn/docker-credential-passage/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "9e60afe36ef3c0a17231293f9b92a3831a471be5c8fc71710c0e4db0aa35316e"
  license "MIT"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X github.com/amrkmn/docker-credential-passage/passage.Version=#{version}"), "./passage/cmd"
  end

  test do
    # Test version command
    assert_match "docker-credential-passage/#{version}", shell_output("#{bin}/docker-credential-passage version")
    
    # Test setup command exists
    assert_match "Setup", shell_output("#{bin}/docker-credential-passage setup 2>&1")
  end
end
