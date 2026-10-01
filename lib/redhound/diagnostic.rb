# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  # Structured protocol diagnostic with severity, stable code, message and optional field.
  Diagnostic = Data.define(:severity, :code, :message, :field)
end
