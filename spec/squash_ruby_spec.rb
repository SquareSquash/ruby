# Copyright 2013 Square Inc.
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

require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

# NOTE: You must set the :disable_failsafe config to true when using RSpec block
# expectations (object.should_receive(method) { ... })

describe Squash::Ruby do
  before :each do
    # reset configuration
    Squash::Ruby.instance_variable_set :@configuration, nil
    Squash::Ruby.configure api_key: 'foobar', environment: 'test', api_host: 'http://test.host'

    # nab an exception
    begin
      raise ArgumentError, "Sploops!"
    rescue => err
      @exception = err
    end
  end

  describe '.notify' do
    before(:each) { Squash::Ruby.configure repository_root: File.join(File.dirname(__FILE__), '..') }

    context "[Squash disabled]" do
      before(:each) { Squash::Ruby.configure disabled: true }

      it "should return false" do
        expect(Squash::Ruby).not_to receive(:http_transmit)
        expect(Squash::Ruby.notify(@exception)).to eql(false)
      end

      it "should log the error if exception_behavior_when_disabled is set to log" do
        Squash::Ruby.configure exception_behavior_when_disabled: 'log'
        expect(Squash::Ruby).to receive(:failsafe_log).once.with('[Squash::Ruby.notify]', a_string_starting_with("Exception raised: Sploops!"))
        allow(Squash::Ruby).to receive(:failsafe_log)
        Squash::Ruby.notify @exception
      end

      it "should raise the error if exception_behavior_when_disabled is set to raise" do
        Squash::Ruby.configure exception_behavior_when_disabled: 'raise'
        expect { Squash::Ruby.notify @exception }.to raise_error("Sploops!")
      end
    end

    it "should return false if the exception has no backtrace" do
      expect(Squash::Ruby).not_to receive(:http_transmit)
      expect(Squash::Ruby.notify(StandardError.new)).to eql(false)
    end

    it "should return false if the exception is not an exception" do
      expect(Squash::Ruby).not_to receive(:http_transmit)
      expect(Squash::Ruby.notify("wut is this?!")).to eql(false)
    end

    it "should raise an exception if the API key is not configured" do
      Squash::Ruby.configure api_key: nil
      expect { Squash::Ruby.notify @exception }.to raise_error(/api_key/)
    end

    it "should raise an exception if the environment is not configured" do
      Squash::Ruby.configure environment: nil
      expect { Squash::Ruby.notify @exception }.to raise_error(/environment/)
    end

    context "[unrolling]" do
      before :each do
        original = nil
        begin
          raise RangeError, "inner"
        rescue
          original = $!
        end

        class << @exception
          attr_accessor :original_exception
        end
        @exception.original_exception = original
      end

      it "should unroll wrapped exceptions" do
        expect(Squash::Ruby).to receive(:http_transmit) do |_, _, body|
          expect(JSON.parse(body)['class_name']).to eql('RangeError')
        end
        Squash::Ruby.notify @exception
      end

      it "should include parent exception information" do
        expect(Squash::Ruby).to receive(:http_transmit) do |_, _, body|
          expect(JSON.parse(body)['parent_exceptions'].size).to eql(1)
          expect(JSON.parse(body)['parent_exceptions'].first['class_name']).to eql('ArgumentError')
          expect(JSON.parse(body)['parent_exceptions'].first['association']).to eql('original_exception')
          expect(JSON.parse(body)['parent_exceptions'].first['message']).to eql('Sploops!')
          expect(JSON.parse(body)['parent_exceptions'].first).to include('ivars')
          expect(JSON.parse(body)['parent_exceptions'].first).to include('backtraces')
        end
        Squash::Ruby.notify @exception
      end
    end

    context "[ignored?]" do
      it "should return true if the exception is ignored because of an ignore block" do
        @exception.instance_variable_set :@_squash_do_not_report, true
        expect(Squash::Ruby).not_to receive(:http_transmit)
        expect(Squash::Ruby.notify(@exception)).to eql(false)
      end

      ['ArgumentError', %w( ArgumentError ), '::ArgumentError', 'StandardError', ArgumentError].each do |klass|
        context "[ignored exception = #{klass.inspect}]" do
          it "should return true if the exception is ignored because of the ignored-exceptions configuration" do
            Squash::Ruby.configure ignored_exception_classes: klass
            expect(Squash::Ruby).not_to receive(:http_transmit)
            expect(Squash::Ruby.notify(@exception)).to eql(false)
          end

          if klass.kind_of?(String)
            it "should return true if the exception is ignored because of the ignored-exception-messages configuration (string)" do
              Squash::Ruby.configure ignored_exception_messages: {klass => 'oo'}
              expect(Squash::Ruby).not_to receive(:http_transmit)
              expect(Squash::Ruby.notify(@exception)).to eql(false)
            end
          end
        end
      end

      it "should return true if the exception is ignored because of the ignored-exception-messages configuration (regexp)" do
        Squash::Ruby.configure ignored_exception_messages: {'ArgumentError' => /oo/}
        expect(Squash::Ruby).not_to receive(:http_transmit)
        expect(Squash::Ruby.notify(@exception)).to eql(false)
      end

      it "should return true if the exception is ignored because of the ignored-exception-procs configuration" do
        Squash::Ruby.configure ignored_exception_procs: lambda { |error, user_data| error.kind_of?(ArgumentError) && user_data[:foo] == 'bar' }

        expect(Squash::Ruby).to receive(:http_transmit).once
        expect(Squash::Ruby.notify(@exception, foo: 'bar')).to eql(false)
        expect(Squash::Ruby.notify(@exception, foo: 'baz')).to eql(true)
      end
    end

    context "[check_user_data]" do
      it "should raise an error if the user data contains :bt" do
        expect(Squash::Ruby).to receive(:failsafe_handler) do |_, error|
          expect(error.to_s).to include('bt')
        end
        Squash::Ruby.notify @exception, bt: 'foo'
      end

      it "should raise an error if the user data contains :mesg" do
        expect(Squash::Ruby).to receive(:failsafe_handler) do |_, error|
          expect(error.to_s).to include('mesg')
        end
        Squash::Ruby.notify @exception, mesg: 'foo'
      end
    end

    describe "[valueify]" do
      before(:each) { Squash::Ruby.configure disable_failsafe: true }

      it "should convert variables to complex value hashes" do
        yaml = (defined?(JRuby) && RUBY_VERSION >= '1.9.0') ? "--- !ruby/regexp '/Hello, world!/'\n" : "--- !ruby/regexp /Hello, world!/\n"
        yaml << "...\n" if RUBY_VERSION >= '1.9.0' && !defined?(JRuby)
        expect(Squash::Ruby.valueify(/Hello, world!/)).to eql("language"   => "ruby",
                                                              "inspect"    => "/Hello, world!/",
                                                              "yaml"       => yaml,
                                                              "class_name" => "Regexp",
                                                              "json"       => "\"(?-mix:Hello, world!)\"",
                                                              "to_s"       => "(?-mix:Hello, world!)")
      end

      it "should not convert JSON primitives" do
        expect(Squash::Ruby.valueify("hello")).to eql("hello")
        expect(Squash::Ruby.valueify(true)).to eql(true)
        expect(Squash::Ruby.valueify(false)).to eql(false)
        expect(Squash::Ruby.valueify(nil)).to eql(nil)
      end

      it "should filter values" do
        allow(Squash::Ruby).to receive(:value_filter).and_return('foo' => 'bar')
        tos  = (RUBY_VERSION < '1.9.0') ? "foobar" : '{"foo"=>"bar"}'
        yaml = (RUBY_VERSION < '1.9.0') ? "--- \nfoo: bar\n" : "---\nfoo: bar\n"
        expect(Squash::Ruby.valueify("hello" => "world")).to eql({
                                                                     "inspect"    => "{\"foo\"=>\"bar\"}",
                                                                     "json"       => "{\"foo\":\"bar\"}",
                                                                     "yaml"       => yaml,
                                                                     "language"   => "ruby",
                                                                     "to_s"       => tos,
                                                                     "class_name" => "Hash"})
      end

      it "should gracefully recover from exceptions raised when calling #to_json" do
        obj = Object.new
        class << obj
          def to_json() raise ArgumentError, "oops!"; end
        end
        expect(Squash::Ruby.valueify(obj)['to_json']).to be_nil
      end

      it "should gracefully recover from exceptions raised when calling #to_yaml" do
        obj = Object.new
        class << obj
          def to_yaml() raise ArgumentError, "oops!"; end
        end
        expect(Squash::Ruby.valueify(obj)['to_yaml']).to be_nil
      end

      it "should gracefully recover from exceptions raised when calling #inspect" do
        obj = Object.new
        class << obj
          def inspect() raise ArgumentError, "oops!"; end
        end
        expect(Squash::Ruby.valueify(obj)['inspect']).to eql("[ArgumentError: oops! raised when calling #inspect]")
      end

      it "should gracefully recover from exceptions raised when calling #to_s" do
        obj = Object.new
        class << obj
          def to_s() raise ArgumentError, "oops!"; end
        end
        expect(Squash::Ruby.valueify(obj)['to_s']).to eql("[ArgumentError: oops! raised when calling #to_s]")
      end

      context '[max_variable_size set]' do
        before(:each) { Squash::Ruby.configure max_variable_size: 10 }

        it "should filter large values" do
          tos = (RUBY_VERSION < '1.9.0') ? '123456' : '["123456"]'
          expect(Squash::Ruby.valueify(%w(123456))).
              to eql('yaml'       => '[exceeded maximum variable size]',
                     'inspect'    => '["123456"]',
                     'json'       => '["123456"]',
                     'to_s'       => tos,
                     'class_name' => 'Array',
                     'language'   => 'ruby')

          tos = (RUBY_VERSION < '1.9.0') ? '1234567' : '[exceeded maximum variable size]'
          expect(Squash::Ruby.valueify(%w(1234567))).
              to eql('yaml'       => '[exceeded maximum variable size]',
                     'inspect'    => '[exceeded maximum variable size]',
                     'json'       => '[exceeded maximum variable size]',
                     'to_s'       => tos,
                     'class_name' => 'Array',
                     'language'   => 'ruby'
                 )
        end

        it "should only filter large nested values when elements_only is set" do
          value     = {
              'short' => %w(123456),
              'long'  => %w(1234567)
          }
          long_tos  = (RUBY_VERSION < '1.9.0') ? '1234567' : '[exceeded maximum variable size]'
          short_tos = (RUBY_VERSION < '1.9.0') ? '123456' : '["123456"]'
          expect(Squash::Ruby.valueify(value, true)).
              to eql(
                     'long'  => {
                         'yaml'       => '[exceeded maximum variable size]',
                         'inspect'    => '[exceeded maximum variable size]',
                         'json'       => '[exceeded maximum variable size]',
                         'to_s'       => long_tos,
                         'class_name' => 'Array',
                         'language'   => 'ruby'
                     },
                     'short' => {
                         'yaml'       => '[exceeded maximum variable size]',
                         'inspect'    => '["123456"]',
                         'json'       => '["123456"]',
                         'to_s'       => short_tos,
                         'class_name' => 'Array',
                         'language'   => 'ruby'
                     }
                 )
        end
      end
    end

    context "[http_transmit]" do
      before(:each) do
        Squash::Ruby.configure api_host:         'https://squash.example.com',
                               transmit_timeout: 15,
                               disable_failsafe: true
      end

      it "should transmit to the API endpoint" do
        http = double('Net:HTTP')
        expect(http).to receive(:request) do |req|
          expect(req.path).to eql('/api/1.0/notify')
          expect(req.body.size).to be > 0
        end.and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = double('Net::HTTP')
        expect(Net::HTTP).to receive(:new).once.with('squash.example.com', 443).and_return(mock)
        expect(mock).to receive(:open_timeout=).once.with(15)
        expect(mock).to receive(:read_timeout=).once.with(15)
        allow(mock).to receive(:use_ssl=)
        expect(mock).to receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception
      end

      it "should support the http_proxy environment variable" do
        Squash::Ruby.configure api_host: 'http://squash.example.com'

        http_proxy        = ENV['http_proxy']
        ENV['http_proxy'] = 'proxy.example.com'

        http = double('Net:HTTP')
        expect(http).to receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = double('Net::HTTP')
        expect(Net::HTTP).to receive(:Proxy).once.with('proxy.example.com', 80, nil, nil).and_return(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(mock)
        allow(mock).to receive(:open_timeout=)
        allow(mock).to receive(:read_timeout=)
        allow(mock).to receive(:use_ssl=)
        expect(mock).to receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['http_proxy'] = http_proxy
      end

      it "should support the https_proxy environment variable" do
        Squash::Ruby.configure api_host: 'https://squash.example.com'

        http_proxy         = ENV['https_proxy']
        ENV['https_proxy'] = 'proxy.example.com'

        http = double('Net:HTTP')
        expect(http).to receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = double('Net::HTTP')
        expect(Net::HTTP).to receive(:Proxy).once.with('proxy.example.com', 443, nil, nil).and_return(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(mock)
        allow(mock).to receive(:open_timeout=)
        allow(mock).to receive(:read_timeout=)
        allow(mock).to receive(:use_ssl=)
        expect(mock).to receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['https_proxy'] = http_proxy
      end

      it "should support the no_proxy environment variable" do
        Squash::Ruby.configure api_host: 'http://squash.example.com'

        http_proxy        = ENV['http_proxy']
        no_proxy          = ENV['no_proxy']
        ENV['http_proxy'] = 'proxy.example.com'
        ENV['no_proxy']   = '.example.com,.foo.com'

        http = double('Net:HTTP')
        expect(http).to receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = double('Net::HTTP')
        expect(Net::HTTP).not_to receive(:Proxy)
        expect(Net::HTTP).to receive(:new).once.and_return(mock)
        allow(mock).to receive(:open_timeout=)
        allow(mock).to receive(:read_timeout=)
        allow(mock).to receive(:use_ssl=)
        expect(mock).to receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['http_proxy'] = http_proxy
        ENV['no_proxy']   = no_proxy
      end

      it "should ignore inapplicable no_proxy values" do
        Squash::Ruby.configure api_host: 'http://squash.example.com'

        http_proxy        = ENV['http_proxy']
        no_proxy          = ENV['no_proxy']
        ENV['http_proxy'] = 'proxy.example.com'
        ENV['no_proxy']   = '.foo.com,.bar.com'

        http = double('Net:HTTP')
        expect(http).to receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = double('Net::HTTP')
        expect(Net::HTTP).to receive(:Proxy).once.with('proxy.example.com', 80, nil, nil).and_return(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(mock)
        allow(mock).to receive(:open_timeout=)
        allow(mock).to receive(:read_timeout=)
        allow(mock).to receive(:use_ssl=)
        expect(mock).to receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['http_proxy'] = http_proxy
        ENV['no_proxy']   = no_proxy
      end

      it "should allowing overriding the timeout_protection used" do
        http = double('Net:HTTP')
        expect(http).to receive(:request) do |req|
          expect(req.path).to eql('/api/1.0/notify')
          expect(req.body.size).to be > 0
        end.and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = double('Net::HTTP')
        expect(Net::HTTP).to receive(:new).once.with('squash.example.com', 443).and_return(mock)
        expect(mock).to receive(:open_timeout=).once.with(15)
        expect(mock).to receive(:read_timeout=).once.with(15)
        allow(mock).to receive(:use_ssl=)
        expect(mock).to receive(:start).once.and_yield(http)

        Squash::Ruby.configure timeout_protection: proc { |timeout, &block| block.call }
        expect(Timeout).not_to receive(:timeout)

        Squash::Ruby.notify @exception
      end

      context "[request body]" do
        before :each do
          @exception.send :instance_variable_set, :@custom_ivar, 'foobar'

          http = double('Net:HTTP')
          expect(http).to receive(:request) do |req|
            @body = req.body
            Net::HTTPSuccess.new('1.1', 200, 'OK')
          end

          mock = double('Net::HTTP')
          allow(Net::HTTP).to receive(:new).and_return(mock)
          allow(mock).to receive(:start).and_yield(http)
          allow(mock).to receive(:open_timeout=)
          allow(mock).to receive(:read_timeout=)
          allow(mock).to receive(:use_ssl=)

          Squash::Ruby.notify @exception, custom_data: 'barfoo'
          @json = JSON.parse(@body)
        end

        it "should transmit information about the exception" do
          expect(@json).to include('class_name')
          expect(@json).to include('message')
          expect(@json).to include('backtraces')
          expect(@json).to include('occurred_at')
          expect(@json).to include('revision')

          expect(@json['environment']).to eql('test')
          expect(@json['client']).to eql('ruby')
        end

        it "should properly tokenize and normalize backtraces" do
          bt         = @exception.backtrace.reject { |line| line.include?('.java') }
          serialized = @json['backtraces'].first['backtrace'].reject { |elem| elem['type'] }
          expect(serialized).to eql(bt.map do |element|
                                      file, line, method = element.split(':')
                                      file.sub! /^#{Regexp.escape Dir.getwd}\//, ''
                                      {
                                          'file'   => file,
                                          'line'   => line.to_i,
                                          'symbol' => method ? method.match(/in `(.+)'$/)[1] : nil
                                      }
                                    end)
        end

        it "should transmit information about the environment" do
          expect(@json).to include('pid')
          expect(@json).to include('hostname')
          expect(@json['env_vars']).to eql(ENV.to_hash)
          expect(@json).to include('arguments')
        end

        it "should transmit the user data" do
          expect(@json['user_data']).to include('custom_data')
        end

        it "should transmit the exception instance variables" do
          expect(@json['ivars']).to include('custom_ivar')
        end
      end
    end

    context "[failsafe_handler]" do
      before(:each) do
        allow(Squash::Ruby).to receive(:http_transmit).and_raise(Net::HTTPError.new("File Not Found", 404))
      end

      after(:each) { FileUtils.rm_f 'squash.failsafe.log' }

      it "should log failsafe errors to the failsafe log" do
        Squash::Ruby.notify @exception
        expect(File.read('squash.failsafe.log')).to include('Net::HTTPError')
        expect(File.read('squash.failsafe.log')).to include('Sploops!')
      end

      it "should raise failsafe errors if the failsafe handler is disabled" do
        Squash::Ruby.configure disable_failsafe: true
        expect { Squash::Ruby.notify @exception }.to raise_error(Net::HTTPError)
        expect(File.exist?('squash.failsafe.log')).to eql(false)
      end

      it "should log failsafe errors to stderr if it can't log to disk" do
        allow(File).to receive(:open).and_raise(Errno::EISDIR)
        stderr = []
        allow($stderr).to receive(:puts) { |out| stderr << out }
        Squash::Ruby.notify @exception
        expect(File.exist?('squash.failsafe.log')).to eql(false)
        expect(stderr).to include("Couldn't write to failsafe log (Is a directory); writing to stderr instead.")
      end
    end

    context "[special backtraces]" do
      before :each do
        http = double('Net:HTTP')
        expect(http).to receive(:request) do |req|
          @body = req.body
          Net::HTTPSuccess.new('1.1', 200, 'OK')
        end

        mock = double('Net::HTTP')
        allow(Net::HTTP).to receive(:new).and_return(mock)
        allow(mock).to receive(:start).and_yield(http)
        allow(mock).to receive(:open_timeout=)
        allow(mock).to receive(:read_timeout=)
        allow(mock).to receive(:use_ssl=)
      end

      it "should properly tokenize JRuby Java backtraces (form 1)" do
        ::JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["arjdbc/jdbc/RubyJdbcConnection.java:191:in `execute'"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"type"   => "obfuscated",
                                                               "file"   => "RubyJdbcConnection.java",
                                                               "line"   => 191,
                                                               "symbol" => "execute",
                                                               "class"  => "arjdbc.jdbc.RubyJdbcConnection"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (form 2)" do
        ::JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["     instance_exec at org/jruby/RubyBasicObject.java:1757"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"type"   => "obfuscated",
                                                               "file"   => "RubyBasicObject.java",
                                                               "line"   => 1757,
                                                               "symbol" => "instance_exec",
                                                               "class"  => "org.jruby.RubyBasicObject"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (form 3)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["org.jruby.RubyHash$27.visit(RubyHash.java:1646)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"type"   => "obfuscated",
                                                               "file"   => "RubyHash.java",
                                                               "line"   => 1646,
                                                               "symbol" => "visit",
                                                               "class"  => "org.jruby.RubyHash$27"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (native method form)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["  sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"type"   => "java_native",
                                                               "symbol" => "invoke0",
                                                               "class"  => "sun.reflect.NativeMethodAccessorImpl"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (ASM invoker)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["  org.jruby.RubyKernel$INVOKER$s$send19.call(RubyKernel$INVOKER$s$send19.gen)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"type" => "asm_invoker",
                                                               "file" => "send19.gen"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 1)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["  rubyjit.ActionController::Rendering$$process_action_7EA12C1BF98F2835D4AE1311F8A1D948CBFB87DA.__file__(vendor/bundle/jruby/1.9/gems/actionpack-3.2.12/lib/action_controller/metal/rendering.rb:10)",
                                  "  rubyjit.ActiveSupport::TaggedLogging$$tagged!_2790A33722B3CBEBECECCFF90F769EB0F50B6FF2.chained_0_ensure_1$RUBY$__ensure__(vendor/bundle/jruby/1.9/gems/activesupport-3.2.12/lib/active_support/tagged_logging.rb:22)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"file"   => "vendor/bundle/jruby/1.9/gems/actionpack-3.2.12/lib/action_controller/metal/rendering.rb",
                                                               "line"   => 10,
                                                               "symbol" => "ActionController::Rendering#process_action"},
                                                              {"file"   => "vendor/bundle/jruby/1.9/gems/activesupport-3.2.12/lib/active_support/tagged_logging.rb",
                                                               "line"   => 22,
                                                               "symbol" => "ActiveSupport::TaggedLogging#tagged!"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 2)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["  rubyjit$AbstractController::Callbacks$$process_action!_9E31DE6CC20BF4BD4675A39AC9F969A1DDA08377$block_0$RUBY$__file__.call(rubyjit$AbstractController::Callbacks$$process_action_9E31DE6CC20BF4BD4675A39AC9F969A1DDA08377$block_0$RUBY$__file__)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{'type'   => 'jruby_block',
                                                               "class"  => "AbstractController::Callbacks",
                                                               "symbol" => "process_action!"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 3)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["  rubyjit.Squash::Ruby::ControllerMethods$$_squash_around_filter!_84CA00BB277BFC0F702CBE86BC4897E3CE15B5AA.chained_0_rescue_1$RUBY$SYNTHETIC__file__(vendor/bundle/jruby/1.9/gems/squash_rails-1.1.0/lib/squash/ruby/controller_methods.rb:138)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"file"   => "vendor/bundle/jruby/1.9/gems/squash_rails-1.1.0/lib/squash/ruby/controller_methods.rb",
                                                               "line"   => 138,
                                                               "symbol" => "Squash::Ruby::ControllerMethods#_squash_around_filter!"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 4)" do
        JRuby = Object.new
        allow(@exception).to receive(:backtrace).and_return(
                                 ["  rubyjit.ActionController::ImplicitRender$$send_action_9AF6F8FC466F72ECECBF8347A4DDB47F06FB9E8F.__file__(vendor/bundle/jruby/1.9/gems/actionpack-3.2.12/lib/action_controller/metal/implicit_render.rb)",
                                  "  rubyjit.ActiveSupport::Notifications::Instrumenter$$instrument!_2E2DDD0482328008F39B59E6DE8E25217A389086.chained_0_ensure_1$RUBY$__ensure__(vendor/bundle/jruby/1.9/gems/activesupport-3.2.12/lib/active_support/notifications/instrumenter.rb)"]
                             )
        Squash::Ruby.notify @exception
        expect(JSON.parse(@body)['backtraces']).to eql([{"name"      => "Active Thread/Fiber",
                                                         "faulted"   => true,
                                                         "backtrace" =>
                                                             [{"file"   => "vendor/bundle/jruby/1.9/gems/actionpack-3.2.12/lib/action_controller/metal/implicit_render.rb",
                                                               "type"   => 'jruby_noline',
                                                               "symbol" => "ActionController::ImplicitRender#send_action"},
                                                              {"file"   => "vendor/bundle/jruby/1.9/gems/activesupport-3.2.12/lib/active_support/notifications/instrumenter.rb",
                                                               "type"   => 'jruby_noline',
                                                               "symbol" => "ActiveSupport::Notifications::Instrumenter#instrument!"}]}])
        Object.send(:remove_const, :JRuby)
      end
    end
  end

  describe '.ignore_exceptions' do
    it "should raise an error if not passed a block" do
      expect { Squash::Ruby.ignore_exceptions }.to raise_error(ArgumentError)
    end

    it "should not report any exceptions if not called with any arguments" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions do
          raise ArgumentError, "sploops"
        end
      rescue => err
        expect(err.send(:instance_variable_get, :@_squash_do_not_report)).to eql(true)
        raised = true
      end
      expect(raised).to eql(true)
    end

    it "should not report exceptions of the given classes" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions(RangeError) do
          raise RangeError, "sploops"
        end
      rescue RangeError => err
        expect(err.send(:instance_variable_get, :@_squash_do_not_report)).to eql(true)
        raised = true
      end
      expect(raised).to eql(true)
    end

    it "should report exceptions that are superclasses of the given classes" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions(RangeError) do
          raise "sploops"
        end
      rescue StandardError => err
        expect(err.send(:instance_variable_get, :@_squash_do_not_report)).to be_falsey
        raised = true
      end
      expect(raised).to eql(true)
    end

    it "should not report exceptions that are subclasses of the given classes" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions(RangeError) do
          raise FloatDomainError, "sploops"
        end
      rescue StandardError => err
        expect(err.send(:instance_variable_get, :@_squash_do_not_report)).to be_nil
        raised = true
      end
      expect(raised).to eql(true)
    end
  end

  describe '.add_user_data' do
    it "should raise an error if not passed a block" do
      expect { Squash::Ruby.add_user_data(foo: 'bar') }.to raise_error(ArgumentError)
    end

    context "[check_user_data]" do
      it "should raise an error if the user data contains :bt" do
        expect { Squash::Ruby.add_user_data(bt: 'bar') { 1 } }.to raise_error(ArgumentError)
      end

      it "should raise an error if the user data contains :mesg" do
        expect { Squash::Ruby.add_user_data(mesg: 'bar') { 1 } }.to raise_error(ArgumentError)
      end
    end

    it "should add the user data to an exception raised in the block" do
      raised = false
      begin
        Squash::Ruby.add_user_data(new_data: 'baz') do
          raise "sploops"
        end
      rescue StandardError => err
        expect(err.send(:instance_variable_get, :@new_data)).to eql('baz')
        raised = true
      end
      expect(raised).to eql(true)
    end
  end

  describe '.fail_silently' do
    it "should raise an error if not passed a block" do
      expect { Squash::Ruby.fail_silently }.to raise_error(ArgumentError)
    end

    it "should report but not raise any exceptions if called with no arguments" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(ArgumentError), {})
      expect do
        Squash::Ruby.fail_silently { raise ArgumentError, "sploops" }
      end.not_to raise_error
    end

    it "should report but not raise any exceptions if called with only options" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(ArgumentError), foo: 'bar')
      expect do
        Squash::Ruby.fail_silently(foo: 'bar') { raise ArgumentError, "sploops" }
      end.not_to raise_error
    end

    it "should only suppress exceptions of the given classes" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(RangeError), {})
      expect do
        Squash::Ruby.fail_silently(RangeError) { raise RangeError, "sploops" }
      end.not_to raise_error

      expect(Squash::Ruby).not_to receive(:notify)
      expect do
        Squash::Ruby.fail_silently(RangeError) { raise ArgumentError, "sploops" }
      end.to raise_error
    end

    it "should allow options" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(RangeError), foo: 'bar')
      expect do
        Squash::Ruby.fail_silently(RangeError, foo: 'bar') { raise RangeError, "sploops" }
      end.not_to raise_error
    end

    it "should not suppress exceptions that are superclasses of the given classes" do
      expect(Squash::Ruby).not_to receive(:notify)
      expect do
        Squash::Ruby.fail_silently(RangeError) { raise "sploops" }
      end.to raise_error
    end

    it "should suppress exceptions that are subclasses of the given classes" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(FloatDomainError), {})
      expect do
        Squash::Ruby.fail_silently(RangeError) { raise FloatDomainError, "sploops" }
      end.not_to raise_error
    end
  end

  describe '.configure' do
    it "should set configuration values" do
      Squash::Ruby.configure custom: 'config'
      expect(Squash::Ruby.send(:configuration, :custom)).to eql('config')
    end

    it "should allow string and symbol values" do
      Squash::Ruby.configure 'custom' => 'config'
      expect(Squash::Ruby.send(:configuration, :custom)).to eql('config')
    end

    it "should merge new values in with existing values" do
      Squash::Ruby.configure custom: 'config', custom2: 'config2'
      Squash::Ruby.configure custom: 'confignew', custom3: 'config3'
      expect(Squash::Ruby.send(:configuration, :custom)).to eql('confignew')
      expect(Squash::Ruby.send(:configuration, :custom2)).to eql('config2')
      expect(Squash::Ruby.send(:configuration, :custom3)).to eql('config3')
    end
  end

  describe ".notify_deploy" do
    it "should do nothing if Squash is disabled" do
      Squash::Ruby.configure disabled: true
      expect(Squash::Ruby).not_to receive :http_transmit
      Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
    end

    it "should POST a notification to the deploy endpoint" do
      http = double('HTTP')
      expect(http).to receive(:request).once do |request|
        expect(JSON.parse(request.body)).to eql(
                                                'project'     => {'api_key' => 'foobar'},
                                                'environment' => {'name' => 'development'},
                                                'deploy'      => {
                                                    'deployed_at' => Time.now.to_s,
                                                    'revision'    => 'abc123',
                                                    'hostname'    => 'myhost.local'
                                                }
                                            )
      end.and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

      mock = double('Net::HTTP')
      expect(Net::HTTP).to receive(:new).once.with('test.host', 80).and_return(mock)
      expect(mock).to receive(:use_ssl=).once.with(false)
      allow(mock).to receive(:open_timeout=)
      allow(mock).to receive(:read_timeout=)
      expect(mock).to receive(:start).once.and_yield(http)

      Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
    end

    it "should report an error given a bad response" do
      http = double('HTTP')
      allow(http).to receive(:request).and_return(Net::HTTPNotFound.new('1.1', 404, 'Not Found'))

      mock = double('Net::HTTP')
      expect(Net::HTTP).to receive(:new).once.with('test.host', 80).and_return(mock)
      expect(mock).to receive(:use_ssl=).once.with(false)
      allow(mock).to receive(:open_timeout=)
      allow(mock).to receive(:read_timeout=)
      expect(mock).to receive(:start).once.and_yield(http)

      expect($stderr).to receive(:puts).once.with(/\[Squash\] Bad response/)
      Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
      FileUtils.rm 'squash.failsafe.log'
    end
  end

  it "should report a timeout to stderr" do
    http = double('HTTP')
    allow(http).to receive(:request).and_raise(Timeout::Error)

    mock = double('Net::HTTP')
    expect(Net::HTTP).to receive(:new).once.with('test.host', 80).and_return(mock)
    expect(mock).to receive(:use_ssl=).once.with(false)
    allow(mock).to receive(:open_timeout=)
    allow(mock).to receive(:read_timeout=)
    expect(mock).to receive(:start).once.and_yield(http)

    expect($stderr).to receive(:puts).once.with(/\[Squash\] Timeout/)
    Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
  end

  describe ".record" do
    it "should accept an exception class, message, and options" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(ArgumentError), foo: 'bar') do |exc, *other|
        expect(exc.to_s).to eql('foobar')
      end
      Squash::Ruby.record ArgumentError, "foobar", foo: 'bar'
    end

    it "should accept an exception class and message" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(ArgumentError), {}) do |exc, *other|
        expect(exc.to_s).to eql('foobar')
      end
      Squash::Ruby.record ArgumentError, "foobar"
    end

    it "should accept a message and options" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(StandardError), foo: 'bar') do |exc, *other|
        expect(exc.to_s).to eql('foobar')
      end
      Squash::Ruby.record "foobar", foo: 'bar'
    end

    it "should accept a message" do
      expect(Squash::Ruby).to receive(:notify).once.with(an_instance_of(StandardError), {}) do |exc, *other|
        expect(exc.to_s).to eql('foobar')
      end
      Squash::Ruby.record "foobar"
    end
  end

  describe ".current_revision" do
    before :each do
      FakeFS.activate!
      FakeFS::FileSystem.clear

      path = File.absolute_path(File.join(File.dirname(__FILE__), '../'))
      FileUtils.mkdir_p path
      Dir.chdir path
    end
    after(:each) { FakeFS.deactivate! }

    context "[revision file specified]" do
      it "should return the contents of the revision file" do
        File.open('test_file', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        Squash::Ruby.configure revision_file: 'test_file'
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should raise an exception for an improperly-formatted revision file" do
        File.open('test_file', 'w') { |f| f.puts 'halp!' }
        Squash::Ruby.configure revision_file: 'test_file'
        expect { Squash::Ruby.current_revision }.to raise_error(/Unknown Git revision/)
      end
    end

    context "[revision specified]" do
      it "should return the revision" do
        Squash::Ruby.configure revision:      'cb586586d2882ebfb5e892c8fc558ada8d2faf95',
                               revision_file: 'test_file'
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should raise an exception for an improperly-formatted revision" do
        Squash::Ruby.configure revision: 'hello'
        expect { Squash::Ruby.current_revision }.to raise_error(/Unknown Git revision/)
      end
    end

    context "[no revision file specified]" do
      it "should use .git/HEAD if it is not a mirrored repository" do
        FileUtils.mkdir_p '/tmp/.git'
        Squash::Ruby.configure repository_root: '/tmp/'
        File.open('/tmp/.git/HEAD', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should use HEAD if it is a mirrored repository" do
        FileUtils.mkdir_p '/tmp'
        Squash::Ruby.configure mirrored_repository: true
        Squash::Ruby.configure repository_root: '/tmp/'
        File.open('/tmp/HEAD', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should return the HEAD if it is a commit" do
        FileUtils.mkdir_p '.git'
        File.open('.git/HEAD', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should return the contents of the ref file if HEAD is a ref" do
        FileUtils.mkdir_p '.git/refs/heads'
        File.open('.git/HEAD', 'w') { |f| f.puts 'ref: refs/heads/branch' }
        File.open('.git/refs/heads/branch', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should search in packed-refs if HEAD is a ref" do
        FileUtils.mkdir_p '.git'
        File.open('.git/HEAD', 'w') { |f| f.puts 'ref: refs/heads/branch' }
        File.open('.git/packed-refs', 'w') do |f|
          f.puts <<-REFS
#cb586586d2882ebfb5e892c8fc558ada8d2faf95 refs/heads/branch
^cb586586d2882ebfb5e892c8fc558ada8d2faf95
cb586586d2882ebfb5e892c8fc558ada8d2faf95 refs/heads/branch
cb586586d2882ebfb5e892c8fc558ada8d2faf96 refs/heads/other
          REFS
        end
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should use `git rev-parse` otherwise" do
        FileUtils.mkdir_p '.git'
        File.open('.git/HEAD', 'w') { |f| f.puts 'ref: refs/heads/unknown' }
        expect(Squash::Ruby).to receive(:`).once.with('git rev-parse refs/heads/unknown').and_return('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
        expect(Squash::Ruby.current_revision).to eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should raise an exception if not running in a Git repo" do
        expect { Squash::Ruby.current_revision }.to raise_error(/You must set the :revision_file configuration/)
      end
    end
  end
end
