# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.afilias.net/info/response_throttled.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'

describe "whois.afilias.net", :aggregate_failures do

  subject do
    file = fixture("responses", "whois.afilias.net/info/response_throttled.txt")
    part = Whois::Record::Part.new(body: File.read(file), host: "whois.afilias.net")
    Whois::Parser.parser_for(part)
  end

  it "matches response_throttled.expected" do
    expect(subject.response_throttled?).to eq(true)
  end
end