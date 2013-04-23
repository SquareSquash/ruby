# Copyright 2012 Square Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

require 'yaml'
require 'socket'
require 'net/https'

require 'json'
begin
  require 'system_timer'
rescue LoadError
  # optional
end

# Container for methods relating to notifying Squash of exceptions.

module Squash
  module Ruby
    # Reserved instance variables that cannot be keys in a user-data hash.
    EXCEPTION_RESERVED_IVARS = %W( mesg bt )
    # Default values for different configuration variables.
    CONFIGURATION_DEFAULTS   = {
        :notify_path                => "/api/1.0/notify",
        :deploy_path                => "/api/1.0/deploy",
        :open_timeout               => 15,
        :transmit_timeout           => 15,
        :ignored_exception_classes  => [],
        :ignored_exception_messages => {},
        :ignored_exception_procs    => [],
        :failsafe_log               => "squash.failsafe.log",
        :repository_root            => Dir.getwd,
        :project_root               => Dir.getwd
    }
    # Types that are serialized directly to JSON, rather than to a hash of
    # object information. Subclasses are not considered members of this array.
    JSON_NATIVE_TYPES        = [String, NilClass, TrueClass, FalseClass, Integer,
                                Fixnum, Float]
    # Array of user-data fields that should be moved out of the user data to
    # become top-level attributes. A Rails client library would expand this
    # constant to include Rails-specific fields, for example.
    TOP_LEVEL_USER_DATA      = []

    # Notifies Squash of an exception.
    #
    # @param [Object] exception The exception. Must at least duck-type an
    #   `Exception` subclass.
    # @param [Hash] user_data Any additional context-specific information about
    #   the exception.
    # @return [true, false] Whether the exception was reported to Squash. (Some
    #   exceptions are ignored and not reported to Squash.)
    # @raise [StandardError] If Squash has not yet been fully configured (see
    #   {.configure}).

    def self.notify(exception, user_data={})
      occurred = Time.now

      return false if configuration(:disabled)
      unless exception.respond_to?(:backtrace)
        failsafe_log 'notify', "Tried to pass notify something other than an exception: #{exception.inspect}"
        return false
      end
      unless exception.backtrace
        failsafe_log 'notify', "Tried to pass notify an exception with no backtrace: #{exception}"
        return false
      end

      raise "The :api_key configuration is required" unless configuration(:api_key)
      raise "The :api_host configuration is required" unless configuration(:api_host)
      raise "The :environment configuration is required" unless configuration(:environment)

      begin
        exception, parents = unroll(exception)
        return false if ignored?(exception, user_data)
        check_user_data user_data

        hsh = exception_info_hash(exception, occurred, user_data, parents)
        http_transmit configuration(:api_host) + configuration(:notify_path), {}, hsh.inject({}) { |h, (k, v)| h[k.to_s] = v; h }.to_json
        return true
      rescue Object => nested_error
        raise if configuration(:disable_failsafe)
        failsafe_handler exception, nested_error
        :failsafe # a perfect example of http://thedailywtf.com/Articles/What_Is_Truth_0x3f_.aspx
      end
    end

    # Raises an exception and immediately catches it and sends it to Squash. The
    # exception is then eaten. This is meant to be used as a hackneyed form of
    # event logging. You can pass in any user data you wish to record with the
    # event.
    #
    # It should be emphasized that Squash is not a logging system, and there are
    # far more appropriate products for this kind of thing, but this method is
    # here nonetheless.
    #
    # @overload record(exception_class, message, user_data={})
    #   Specify both the exception class and the message.
    #   @param [Class] exception_class The exception class to raise.
    #   @param [String] message The exception message.
    #   @param [Hash] user_data Additional information to give to {.notify}.
    # @overload record(message, user_data={})
    #   Specify only the message. The exception class will be `StandardError`.
    #   @param [String] message The exception message.
    #   @param [Hash] user_data Additional information to give to {.notify}.

    def self.record(exception_class_or_message, message_or_options=nil, data=nil)
      if message_or_options && data
        exception_class = exception_class_or_message
        message         = message_or_options
      elsif message_or_options.kind_of?(String)
        message         = message_or_options
        exception_class = exception_class_or_message
      elsif message_or_options.kind_of?(Hash)
        data            = message_or_options
        message         = exception_class_or_message
        exception_class = StandardError
      elsif message_or_options.nil?
        message         = exception_class_or_message
        exception_class = StandardError
      else
        raise ArgumentError
      end

      begin
        raise exception_class, message
      rescue exception_class => error
        notify error, data || {}
      end
    end

    # Suppresses reporting of certain exceptions within a block of code. Any
    # exceptions raised in the block will continue to be raised, however.
    #
    # Let's take a few examples. If `exception_classes` is `[RangeError]`, then
    # obviously any raised `RangeError`s will not be reported. If
    # `StandardError` is raised, it _will_ be reported, because it's a
    # superclass of `RangeError`. If `FloatDomainError` is raised, it _will not_
    # be reported because it is a _subclass_ of `RangeError`. Confusing? Sure,
    # but I'm pretty sure this is the behavior most people would expect.
    #
    # @param [Array<Class>] exception_classes A list of exception classes to
    #   ignore. If not provided, ignores all exceptions raised in the block.
    # @yield The code to ignore exceptions in.
    # @return The result of the block.
    # @raise [ArgumentError] If no block is provided.

    def self.ignore_exceptions(exception_classes=nil)
      raise ArgumentError, "Squash::Ruby.ignore_exceptions must be called with a block" unless block_given?
      exception_classes = [exception_classes] if exception_classes.kind_of?(Class)

      begin
        yield
      rescue Object => err
        err.instance_variable_set(:@_squash_do_not_report, true) if exception_classes.nil? || exception_classes.map { |e| e.ancestors }.flatten.include?(err.class)
        raise
      end
    end

    # Adds user data to any exception raised within a block of code, and
    # re-raises the exception.
    #
    # @param [Hash] user_data User data to add to an exception.
    # @yield The code to run.
    # @return The result of the block.
    # @raise [ArgumentError] If `data` contains the keys `mesg` or `bt`.

    def self.add_user_data(user_data)
      raise ArgumentError, "Squash::Ruby.add_user_data must be called with a block" unless block_given?
      check_user_data user_data

      begin
        yield
      rescue Object => err
        user_data.each { |ivar, val| err.send :instance_variable_set, :"@#{ivar}", val }
        raise
      end
    end

    # @overload fail_silently(exception_classes=nil, options={})
    #   Executes the block, suppressing and silently reporting any exceptions to
    #   Squash. This allows you to ensure that a non-critical block of code
    #   does not halt your application while still receiving exception
    #   notifications in Squash.
    #   @param [Array<Class>] exception_classes A list of exception classes to
    #     report silently. Exceptions _not_ of these classes (or their
    #     subclasses) will raise (and presumably be handled by Squash elsewhere
    #     in your code).
    #   @param [Hash] options Additional options to pass to {.notify}.
    #   @yield The code to suppress exceptions in.
    #   @return The result of the block.
    # @raise [ArgumentError] If no block is provided.

    def self.fail_silently(exception_classes_or_options=nil, options=nil)
      raise ArgumentError, "Squash::Ruby.exception_classes must be called with a block" unless block_given?

      exception_classes = if options
                            exception_classes_or_options
                          else
                            if exception_classes_or_options.kind_of?(Hash) then
                              options = exception_classes_or_options
                              nil
                            else
                              exception_classes_or_options
                            end
                          end
      options           ||= {}

      exception_classes = [exception_classes] if exception_classes.kind_of?(Class)

      begin
        yield
      rescue Object => err
        if exception_classes.nil? || exception_classes.detect { |e| err.kind_of?(e) }
          Squash::Ruby.notify err, options
        else
          raise
        end
      end
    end

    # Sets configuration options for the client from a hash. See the README for
    # a list of configuration options. Subsequent calls will merge in new
    # configuration options.
    #
    # You must at a minimum specify the `:api_key` and `:environment` settings
    # (see the README.md file).
    #
    # @param [Hash] options Configuration options.

    def self.configure(options)
      @configuration = (@configuration || CONFIGURATION_DEFAULTS.dup).merge(options.inject({}) { |hsh, (k, v)| hsh[(k.to_sym rescue k)] = v; hsh })
    end

    # @private
    def self.check_user_data(data)
      bad_ivars = EXCEPTION_RESERVED_IVARS.select { |name| data.keys.map { |k| k.to_s }.include? name }
      raise ArgumentError, "The following cannot be used as user-data keys: #{bad_ivars.join(', ')}" unless bad_ivars.empty?
    end

    protected

    # Posts an exception or deploy notification to the API endpoint. Only POST
    # requests are supported. This method is used internally only. It is
    # documented so that, in the event you wish to use an alternative HTTP
    # library (other than `Net::HTTP`), you can override this method.
    #
    # This method will make a `POST` request to the given URL. The request will
    # contain the given headers and body. It should not eat any exceptions
    # relating to HTTP connectivity issues.
    #
    # Your implementation should also respect the value of the
    # `transmit_timeout` configuration, which is accessible using
    # `configuration(:transmit_timeout)`.
    #
    # @param [String] url The URL to post to. Could be an HTTP or HTTPS URL.
    # @param [Hash<String, String>] headers The request headers.
    #   `Content-Type: application/json` is added by default.
    # @param [String] body The request body.
    # @return [true, false] Whether or not the response was successful.

    def self.http_transmit(url, headers, body)
      uri  = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http_options(uri).each { |k, v| http.send :"#{k}=", v }

      block = lambda do
        http.start do |http|
          request = Net::HTTP::Post.new(uri.request_uri)
          request.add_field 'Content-Type', 'application/json'
          headers.each { |k, v| request.add_field k, v }
          request.body = body
          response     = http.request request
          if response.kind_of?(Net::HTTPSuccess)
            return true
          else
            self.failsafe_log 'http_transmit', "Response from server: #{response.code}"
            return false
          end
        end
      end

      if defined?(SystemTimer)
        SystemTimer.timeout_after configuration(:open_timeout), &block
      else
        block.call
      end
    end

    # Notifies Squash of a new deploy. Squash will then determine which bug
    # fixes have been deployed and then mark those bugs as fix-deployed.
    #
    # @param [String] env The name of the environment that was deployed.
    # @param [String] revision The repository revision that was deployed.
    # @param [String] from_host The hostname of the computer that performed the
    #   deploy.
    # @raise [StandardError] If an invalid response is received from the HTTP
    #   request.

    def self.notify_deploy(env, revision, from_host)
      return if configuration(:disabled)

      success = http_transmit(
          configuration(:api_host) + configuration(:deploy_path),
          {},
          {
              'project'     => {'api_key' => configuration(:api_key)},
              'environment' => {'name' => env},
              'deploy'      => {
                  'deployed_at' => Time.now,
                  'revision'    => revision,
                  'hostname'    => from_host
              }
          }.to_json
      )
      $stderr.puts "[Squash] Bad response; see failsafe log" unless success
    rescue Timeout::Error
      $stderr.puts "[Squash] Timeout when trying to notify of the deploy"
    end

    # @abstract
    #
    # Override this method to filter sensitive information from any data that
    # Squash intends to add to an occurrence. This method receives every object
    # that Squash is about to serialize -- instance variables, user data,
    # (for Rails) sessions, params, etc., just before serialization and
    # transmission.
    #
    # This method gives you the opportunity to alter the object before
    # serialization, for example to remove sensitive information. It's probably a
    # good idea to clone the object, modify it, and then return the clone, so that
    # the original object remains unmodified.
    #
    # The base implementation returns `value` unmodified.
    #
    # @param value A value that is about to be serialized for transmission.
    # @return The object to serialize (filtered as necessary). May be a different
    #   object.
    def self.value_filter(value) value end

    private

    def self.http_options(uri)
      options = {:use_ssl      => uri.scheme == 'https',
                 :open_timeout => configuration(:transmit_timeout),
                 :read_timeout => configuration(:transmit_timeout)}
      options[:verify_mode] = OpenSSL::SSL::VERIFY_NONE if configuration(:skip_ssl_verification)
      options
    end

    def self.configuration(key)
      (@configuration || CONFIGURATION_DEFAULTS)[key] || CONFIGURATION_DEFAULTS[key]
    end

    def self.ignored?(exception, user_data)
      return true if exception.instance_variable_get(:@_squash_do_not_report)

      return true if Array(configuration(:ignored_exception_classes)).map do |class_name|
        constantize class_name
      end.compact.any? { |klass| exception.kind_of?(klass) }

      return true if configuration(:ignored_exception_messages).any? do |class_name, ignored_messages|
        ignored_messages = Array(ignored_messages).map { |str| str.kind_of?(String) ? Regexp.compile(str) : str }
        (klass = constantize(class_name)) && exception.kind_of?(klass) && ignored_messages.any? { |msg| exception.to_s =~ msg }
      end

      return true if Array(configuration(:ignored_exception_procs)).any? do |proc|
        proc.call(exception, user_data)
      end

      return false
    end

    def self.exception_info_hash(exception, occurred, user_data, parents)
      top_level_user_data = Hash.new
      user_data.delete_if do |key, value|
        if TOP_LEVEL_USER_DATA.include?(key.to_s)
          top_level_user_data[key.to_s] = valueify(value, true)
          true
        else
          false
        end
      end

      environment_data.merge(top_level_user_data).merge(
          'class_name'        => exception.class.to_s,
          'message'           => exception.to_s,
          'backtraces'        => [{
                                      'name'      => "Active Thread/Fiber",
                                      'faulted'   => true,
                                      'backtrace' => prepare_backtrace(exception.backtrace)
                                  }],
          'occurred_at'       => occurred,
          'revision'          => current_revision,

          'environment'       => configuration(:environment).to_s,
          'api_key'           => configuration(:api_key).to_s,
          'client'            => client_name,

          'ivars'             => instance_variable_hash(exception),
          'user_data'         => valueify(user_data, true),

          'parent_exceptions' => parents.nil? ? nil : parents.map do |parent|
            {'class_name'  => parent.class.to_s,
             'message'     => parent.to_s,
             'backtraces'  => [{
                                   'name'      => "Active Thread/Fiber",
                                   'faulted'   => true,
                                   'backtrace' => prepare_backtrace(parent.backtrace)
                               }],
             'association' => 'original_exception',
             'ivars'       => instance_variable_hash(parent)}
          end
      )
    end

    def self.prepare_backtrace(bt)
      if defined?(JRuby)
        bt.map(&:strip).map do |element|
          if element =~ /^((?:[a-z0-9_$]+\.)*(?:[a-z0-9_$]+))\.(\w+)\((\w+.java):(\d+)\)$/i
            # special JRuby backtrace element of the form "org.jruby.RubyHash$27.visit(RubyHash.java:1646)"
            {
                'type'   => 'obfuscated',
                'file'   => $3,
                'line'   => $4.to_i,
                'symbol' => $2,
                'class'  => $1
            }
          elsif element =~ /^(.+?)\.(\w+)\(Native Method\)$/
            {
                'type'   => 'java_native',
                'symbol' => $2,
                'class'  => $1
            }
          elsif element =~ /^rubyjit[$.](.+?)\$\$(\w+?[?!]?)_[0-9A-F]{40}.+?__(?:file|ensure)__\.call\(.+\)$/
            {
                'type'   => 'jruby_block',
                'class'  => $1,
                'symbol' => $2
            }
          elsif element =~ /^rubyjit[$.](.+?)\$\$(\w+?[?!]?)_[0-9A-F]{40}.+?__(?:file|ensure)__\((.+?):(\d+)\)$/
            {
                'file'   => $3,
                'line'   => $4.to_i,
                'symbol' => "#{$1}##{$2}"
            }
          elsif element =~ /^.+\.call\(.+?(\w+)\.gen\)$/
            {
                'type' => 'asm_invoker',
                'file' => $1 + '.gen'
            }
          elsif element =~ /^rubyjit[$.](.+?)\$\$(\w+?[?!]?)_[0-9A-F]{40}.+?__(?:file|ensure)__\((.+?)\)$/
            {
                'file'   => $3,
                'type'   => 'jruby_noline',
                'symbol' => "#{$1}##{$2}"
            }
          else
            if element.include?(' at ')
              method, fileline = element.split(' at ')
              method.lstrip!
              file, line = fileline.split(':')
            else
              file, line, method = element.split(':')
              if method =~ /^in `(.+)'$/
                method = $1
              end
              method = nil if method && method.empty?
            end
            line = line.to_i
            line = nil if line < 1
            if method =~ /^in `(.+)'$/
              method = $1
            end
            method = nil if method && method.empty?

            # it could still be a java backtrace, even if it's not the special format
            if file[-5, 5] == '.java'
              {
                  'type'   => 'obfuscated',
                  'file'   => file.split('/').last,
                  'line'   => line,
                  'symbol' => method,
                  'class'  => file.sub(/\.java$/, '').gsub('/', '.')
              }
            else
              # ok now we're sure it's a ruby backtrace
              file.slice! 0, configuration(:project_root).length + 1 if file[0, configuration(:project_root).length + 1] == configuration(:project_root) + '/'
              {
                  'file'   => file,
                  'line'   => line,
                  'symbol' => method
              }
            end
          end
        end
      else
        bt.map do |element|
          file, line, method = element.split(':')
          line               = line.to_i
          line = nil if line < 1

          file.slice! 0, configuration(:project_root).length + 1 if file[0, configuration(:project_root).length + 1] == configuration(:project_root) + '/'

          if method =~ /^in `(.+)'$/
            method = $1
          end
          method = nil if method && method.empty?
          {
              'file'   => file,
              'line'   => line,
              'symbol' => method
          }
        end
      end
    end

    def self.valueify(instance, elements_only=false)
      if JSON_NATIVE_TYPES.any? { |klass| instance.class == klass }
        instance
      elsif instance.kind_of?(Hash) && elements_only
        instance.inject({}) { |hsh, (k, v)| hsh[k.to_s] = valueify(v); hsh }
      elsif instance.kind_of?(Array) && elements_only
        instance.map { |i| valueify(i) }
      else
        filtered       = value_filter(instance)
        yaml           = begin filtered.to_yaml; rescue Exception; nil end
        json           = begin filtered.to_json; rescue Exception; nil end
        inspect_result = begin filtered.inspect; rescue Exception => e; "[#{e.class}: #{e} raised when calling #inspect]" end
        to_s_result    = begin filtered.to_s; rescue Exception => e; "[#{e.class}: #{e} raised when calling #to_s]" end

        {
            'language'   => 'ruby',
            'class_name' => filtered.class.to_s,
            'inspect'    => inspect_result,
            'yaml'       => yaml,
            'json'       => json,
            'to_s'       => to_s_result
        }
      end
    end

    def self.instance_variable_hash(object)
      object.instance_variables.inject({}) do |hsh, cur|
        hsh[cur.to_s[1..-1]] = valueify(object.send(:instance_variable_get, cur.to_sym))
        hsh
      end
    end

    def self.constantize(class_name)
      return class_name if class_name.kind_of?(Class)

      parts    = class_name.split('::').reject { |i| i.empty? }
      constant = Object
      while parts.any? do
        begin
          constant = constant.const_get(parts.shift)
        rescue NameError
          return nil
        end
      end
      constant
    end

    # @private
    def self.environment_data
      {
          'pid'       => Process.pid,
          'hostname'  => Socket.gethostname,
          'env_vars'  => ENV.inject({}) { |hsh, (k, v)| hsh[k.to_s] = valueify(v); hsh },
          'arguments' => ARGV.join(' ')
      }
    end

    # @private
    def self.failsafe_handler(original_error, nested_error)
      log_entries = [
          "#{Time.now.to_s} - Original error: (#{original_error.class.to_s}) #{original_error.to_s}",
          (original_error.backtrace || []).map { |l| '  ' + l }.join("\n"),
          "#{Time.now.to_s} - Error raised when reporting original error: (#{nested_error.class.to_s}) #{nested_error.to_s}",
          nested_error.backtrace.map { |l| '  ' + l }.join("\n"),
          "--- END SQUASH FAILSAFE ERROR ---"
      ]
      log_entries.each { |message| self.failsafe_log 'failsafe_handler', message }
    end

    # @private
    def self.failsafe_log(tag, message)
      File.open(configuration(:failsafe_log), 'a') do |f|
        f.puts "#{Time.now.to_s}\t[#{tag}]\t#{message}"
      end
    rescue Object => err
      $stderr.puts "Couldn't write to failsafe log (#{err.to_s}); writing to stderr instead."
      $stderr.puts "#{Time.now.to_s}\t[#{tag}]\t#{message}"
    end

    # @private
    def self.current_revision
      revision = if configuration(:revision)
                   configuration(:revision)
                 elsif configuration(:revision_file)
                   File.read(configuration(:revision_file)).chomp.strip
                 else
                   head_file = File.join(configuration(:repository_root), '.git', 'HEAD')
                   if File.exist?(head_file)
                     rev = File.read(head_file).chomp.strip
                     if rev =~ /^ref: (.+?)$/
                       rev      = nil # in case we need to shell
                       ref      = $1
                       ref_file = File.join(configuration(:repository_root), '.git', ref)
                       if File.exist?(ref_file)
                         rev = File.read(ref_file).chomp.strip
                       elsif File.exist?(File.join(configuration(:repository_root), '.git', 'packed-refs'))
                         revs = File.join(configuration(:repository_root), '.git', 'packed-refs')
                         File.open(revs) do |f|
                           f.each_line do |line|
                             next if line[0, 1] == '#'
                             next if line[0, 1] == '^'
                             next unless line.chomp[-(ref.length)..-1] == ref
                             rev = line[0, 40]
                             break
                           end
                         end
                       end
                     end
                     rev ||= `git rev-parse #{ref}`.strip # shell as a last resort
                     rev
                   else
                     raise "You must set the :revision_file configuration if the code is not running in a Git checkout"
                   end
                 end
      raise "Unknown Git revision #{revision.inspect}" unless revision =~ /^[0-9a-f]{40}$/
      revision
    end

    # @private
    def self.unroll(exception)
      if exception.respond_to?(:original_exception)
        [exception.original_exception, [exception]]
      else
        [exception, nil]
      end
    end

    # @private
    def self.client_name() 'ruby' end
  end
end
