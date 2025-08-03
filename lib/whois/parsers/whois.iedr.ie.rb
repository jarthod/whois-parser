require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the whois.iedr.ie server.
    # Now uses ICANN compliant format.
    class WhoisIedrIe < BaseIcannCompliant
      include Scanners::Scannable

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^Not found: (.+)/,
          pattern_disclaimer: /^% Important Notice/
      }

    end

  end
end
