class Trusty < Formula
  desc "AI Code Verification CLI — verify AI-generated code with static analysis, semantic checks, and behavioral verification"
  homepage "https://github.com/WorldOccupier/trusty"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/WorldOccupier/trusty/releases/download/v0.1.0/trusty-darwin-arm64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/WorldOccupier/trusty/releases/download/v0.1.0/trusty-darwin-amd64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/WorldOccupier/trusty/releases/download/v0.1.0/trusty-linux-arm64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/WorldOccupier/trusty/releases/download/v0.1.0/trusty-linux-amd64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "trusty"
  end

  test do
    assert_match "trusty", shell_output("#{bin}/trusty --help")
  end
end
