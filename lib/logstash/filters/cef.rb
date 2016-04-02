# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'

# This is a CEF parsing filter. It takes an existing field which contains CEF and
# expands it into an actual data structure within the Logstash event.
#
# Inspired from: https://github.com/logstash-plugins/logstash-codec-cef
#
# A CEF string such as:
#
# 'CEF: 0|Figgity Foo Bar Inc.|ThingyThang|1.0.0|Firewall|Something Bad Happened|Informative|foo=bar baz=ah Hellz Nah'
#
#  results in the following parsed structure.
# {
#   "cef_version"=>"0",
#   "cef_vendor"=>"Figgity Foo Bar Inc.",
#   "cef_product"=>"ThingyThang",
#   "cef_device_version"=>"1.0.0",
#   "cef_sigid"=>"Firewall",
#   "cef_name"=>"Something Bad Happened",
#   "cef_severity"=>"Informative",
#   "cef_syslog"=>"CEF:",
#   "cef_ext"=> {
#     "foo"=>"bar",
#     "baz"=>"ah Hellz Nah"
#   }
# }
#
#
# By default it will place the parsed CEF in the root (top level) of the Logstash event, but this
# filter can be configured to place the CEF into any arbitrary event field, using the
# `target` configuration.
#
class LogStash::Filters::CEF < LogStash::Filters::Base
    # Implementation of a Logstash codec for the ArcSight Common Event Format (CEF)
    # Based on Revision 20 of Implementing ArcSight CEF, dated from June 05, 2013
    # https://protect724.hp.com/servlet/JiveServlet/downloadBody/1072-102-6-4697/CommonEventFormat.pdf
    config_name 'cef'

    # The configuration for the CEF filter:
    # [source,ruby]
    #     source => source_field
    #
    # For example, if you have CEF data in the `message` field:
    # [source,ruby]
    #     filter {
    #       cef {
    #         source => "message"
    #       }
    #     }
    #
    # The above would parse the cef from the `message` field
    config :source, validate: :string, required: true

    # Define the target field for placing the parsed data. If this setting is
    # omitted, the CEF data will be stored at the root (top level) of the event.
    #
    # For example, if you want the data to be put in the `doc` field:
    # [source,ruby]
    #     filter {
    #       cef {
    #         target => "doc"
    #       }
    #     }
    #
    # CEF in the value of the `source` field will be expanded into a
    # data structure in the `target` field.
    #
    # NOTE: if the `target` field already exists, it will be overwritten!
    config :target, validate: :string

    # Append values to the `tags` field when there has been no
    # successful match
    config :tag_on_failure, validate: :array, default: ['_cefparsefailure']

    def register
        # Nothing to do here
    end # def register

    def filter(event)
        @logger.debug? && @logger.debug('Running CEF filter', event: event)

        source = event[@source]
        return unless source

        begin
            parsed = cef_decode(source)
            print parsed
        rescue => e
            @tag_on_failure.each { |tag| event.tag(tag) }
            @logger.warn('Error parsing CEF', source: @source, raw: source, exception: e)
            return
        end

        if @target
            event[@target] = parsed
        else
            unless parsed.is_a?(Hash)
                @tag_on_failure.each { |tag| event.tag(tag) }
                @logger.warn('Parsed CEF object/hash requires a target configuration option', source: @source, raw: source)
                return
            end

            # TODO: (colin) the timestamp initialization should be DRY'ed but exposing the similar code
            # in the Event#init_timestamp method. See https://github.com/elastic/logstash/issues/4293

            # a) since the parsed hash will be set in the event root, first extract any @timestamp field to properly initialized it
            parsed_timestamp = parsed.delete(LogStash::Event::TIMESTAMP)
            begin
                timestamp = parsed_timestamp ? LogStash::Timestamp.coerce(parsed_timestamp) : nil
            rescue LogStash::TimestampParserError => e
                timestamp = nil
            end

            # b) then set all parsed fields in the event
            parsed.each { |k, v| event[k] = v }
            # c) finally re-inject proper @timestamp
            if parsed_timestamp
                if timestamp
                    event.timestamp = timestamp
                else
                    event.timestamp = LogStash::Timestamp.new
                    @logger.warn("Unrecognized #{LogStash::Event::TIMESTAMP} value, setting current time to #{LogStash::Event::TIMESTAMP}, original in #{LogStash::Event::TIMESTAMP_FAILURE_FIELD} field", value: parsed_timestamp.inspect)
                    event.tag(LogStash::Event::TIMESTAMP_FAILURE_TAG)
                    event[LogStash::Event::TIMESTAMP_FAILURE_FIELD] = parsed_timestamp.to_s
                end
            end
      end

        # filter_matched should go in the last line of our successful code
        filter_matched(event)

        @logger.debug? && @logger.debug('Event after CEF filter', event: event)
    end # def filter

    private

    # CEF deocoding logic
    def cef_decode(data)
        # Strip any quotations at the start and end, flex connectors seem to send this
        data = data[1..-2] if data[0] == '"'
        event = {}

        # Split by the pipes
        event['cef_version'], event['cef_vendor'], event['cef_product'], event['cef_device_version'], event['cef_sigid'], event['cef_name'], event['cef_severity'], message = data.split /(?<!\\)[\|]/

        # Try and parse out the syslog header if there is one
        if event['cef_version'].include? ' '
            event['cef_syslog'], unused, event['cef_version'] = event['cef_version'].rpartition(' ')
        end

        # Get rid of the CEF bit in the version
        version = event['cef_version'].sub /^CEF:/, ''
        event['cef_version'] = version

        # Strip any whitespace from the message
        if !message.nil? && message.include?('=')
            message = message.strip

            # If the last KVP has no value, add an empty string, this prevents hash errors below
            message += ' ' if message.end_with?('=')

            # Now parse the key value pairs into it
            extensions = {}
            message = message.split(/ ([\w\.]+)=/)
            key, value = message.shift.split('=', 2)
            extensions[key] = value

            Hash[*message].each { |k, v| extensions[k] = v }

            # And save the new has as the extensions
            event['cef_ext'] = extensions
        end

        return event
     end
end # class LogStash::Filters::Example
