# rbs_inline: enabled
# frozen_string_literal: true

module Redhound
  module Util
    module SafeText
      module_function

      # 端末制御文字による表示改ざんを防ぐため、印字可能 ASCII 以外を '.' に置換する
      # @rbs (Array[Integer] bytes) -> String
      def printable(bytes)
        bytes.map { |b| b.between?(0x20, 0x7e) ? b.chr : '.' }.join
      end
    end
  end
end
