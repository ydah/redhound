# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Base exception for Redhound operational and configuration errors.
  class Error < StandardError; end
  # Capture-device or live-operation failure.
  class CaptureError < Error; end
  # @api private
  class RotationComplete < CaptureError; end
  # Insufficient permission to access the capture device.
  class PermissionDenied < CaptureError; end
  # Requested capture interface does not exist.
  class InterfaceNotFound < CaptureError; end
  # Requested platform or capture capability is unavailable.
  class UnsupportedPlatform < CaptureError; end
  # Malformed or unsupported capture-file structure.
  class FileFormatError < Error; end
  # Invalid command-line or library configuration.
  class ConfigurationError < Error; end
  # Invalid cBPF program or unsupported filter operation.
  class FilterError < Error; end
  # Filter exceeds the target platform instruction limit.
  class FilterTooLarge < FilterError; end
  # Capture-filter syntax error with original expression and byte position.
  class FilterSyntaxError < FilterError
    # Original filter expression and zero-based error position.
    attr_reader :expression, :position

    # @rbs (String message, ?expression: String?, ?position: Integer?) -> void
    # Create a syntax diagnostic suitable for a caret display.
    def initialize(message, expression: nil, position: nil)
      @expression = expression
      @position = position
      super(message)
    end
  end
end
