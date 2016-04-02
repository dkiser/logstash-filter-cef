# encoding: utf-8

require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/cef'
require 'logstash/timestamp'

describe LogStash::Filters::CEF do
    describe 'parse message into the event' do
        config <<-CONFIG
      filter {
        cef {
          # Parse message as CEF string
          source => "message"
        }
      }
    CONFIG

        sample 'CEF: 0|Figgity Foo Bar Inc.|ThingyThang|1.0.0|Firewall|Something Bad Happened|Informative|foo=bar baz=ah Hellz Nah' do
            insist { subject['cef_version'] } == '0'
            insist { subject['cef_vendor'] } == 'Figgity Foo Bar Inc.'
            insist { subject['cef_product'] } == 'ThingyThang'
            insist { subject['cef_device_version'] } == '1.0.0'
            insist { subject['cef_sigid'] } == 'Firewall'
            insist { subject['cef_name'] } == 'Something Bad Happened'
            insist { subject['cef_syslog'] } == "CEF:"
            insist { subject['cef_severity'] } == 'Informative'
            insist { subject['cef_ext']['foo'] } == 'bar'
            insist { subject['cef_ext']['baz'] } == 'ah Hellz Nah'
        end
    end

    context 'using message field source' do
        subject(:filter) { LogStash::Filters::CEF.new(config) }

        let(:config) { { 'source' => 'message' } }
        let(:event) { LogStash::Event.new('message' => message) }

        before(:each) do
            filter.register
            filter.filter(event)
        end
    end
end
