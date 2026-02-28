require_relative 'base'

module Whois
  class Parsers

    class WhoisOvhCom < Base

      def self.valid?(part)
        part.host == "whois.ovh.com"
      end

      property_supported :registrar do
        Parser::Registrar.new(
          id:           node("Registrar IANA ID"),
          name:         Array(node("Registrar")),
          url:          node("Registrar URL")
        )
      end

      property_supported :domain do
        node("Domain Name")
      end

      property_supported :created_on do
        parse_time(node("Creation Date"))
      end

      property_supported :updated_on do
        parse_time(node("Updated Date"))
      end

      property_supported :expires_on do
        parse_time(node("Registrar Registration Expiration Date"))
      end

      property_supported :nameservers do
        Array(part.body.scan(/^Name Server:\s*(.+)$/i).flatten).map(&:downcase)
      end

      private

      def node(field)
        part.body[/^#{Regexp.escape(field)}:\s*(.+)$/i, 1]&.strip
      end

    end

  end
end
