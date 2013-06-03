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

require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

# NOTE: You must set the :disable_failsafe config to true when using RSpec block
# expectations (object.should_receive(method) { ... })

describe Squash::Ruby do
  before :each do
    # reset configuration
    Squash::Ruby.instance_variable_set :@configuration, nil
    Squash::Ruby.configure :api_key => 'foobar', :environment => 'test', :api_host => 'http://test.host'

    # nab an exception
    begin
      raise ArgumentError, "Sploops!"
    rescue => err
      @exception = err
    end
  end

  describe '.notify' do
    before(:each) { Squash::Ruby.configure :repository_root => File.join(File.dirname(__FILE__), '..') }

    it "should return false if Squash is disabled" do
      Squash::Ruby.configure :disabled => true
      Squash::Ruby.should_not_receive(:http_transmit)
      Squash::Ruby.notify(@exception).should be_false
    end

    it "should return false if the exception has no backtrace" do
      Squash::Ruby.should_not_receive(:http_transmit)
      Squash::Ruby.notify(StandardError.new).should be_false
    end

    it "should return false if the exception is not an exception" do
      Squash::Ruby.should_not_receive(:http_transmit)
      Squash::Ruby.notify("wut is this?!").should be_false
    end

    it "should raise an exception if the API key is not configured" do
      Squash::Ruby.configure :api_key => nil
      lambda { Squash::Ruby.notify @exception }.should raise_error(/api_key/)
    end

    it "should raise an exception if the environment is not configured" do
      Squash::Ruby.configure :environment => nil
      lambda { Squash::Ruby.notify @exception }.should raise_error(/environment/)
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
        Squash::Ruby.should_receive(:http_transmit).with do |_, _, body|
          JSON.parse(body)['class_name'] == 'RangeError'
        end
        Squash::Ruby.notify @exception
      end

      it "should include parent exception information" do
        Squash::Ruby.should_receive(:http_transmit).with do |_, _, body|
          JSON.parse(body)['parent_exceptions'].size == 1 &&
              JSON.parse(body)['parent_exceptions'].first['class_name'] == 'ArgumentError' &&
              JSON.parse(body)['parent_exceptions'].first['association'] == 'original_exception' &&
              JSON.parse(body)['parent_exceptions'].first['message'] == 'Sploops!' &&
              JSON.parse(body)['parent_exceptions'].first.include?('ivars') &&
              JSON.parse(body)['parent_exceptions'].first.include?('backtraces')
        end
        Squash::Ruby.notify @exception
      end
    end

    context "[ignored?]" do
      it "should return true if the exception is ignored because of an ignore block" do
        @exception.instance_variable_set :@_squash_do_not_report, true
        Squash::Ruby.should_not_receive(:http_transmit)
        Squash::Ruby.notify(@exception).should be_false
      end

      ['ArgumentError', %w( ArgumentError ), '::ArgumentError', 'StandardError', ArgumentError].each do |klass|
        context "[ignored exception = #{klass.inspect}]" do
          it "should return true if the exception is ignored because of the ignored-exceptions configuration" do
            Squash::Ruby.configure :ignored_exception_classes => klass
            Squash::Ruby.should_not_receive(:http_transmit)
            Squash::Ruby.notify(@exception).should be_false
          end

          if klass.kind_of?(String)
            it "should return true if the exception is ignored because of the ignored-exception-messages configuration (string)" do
              Squash::Ruby.configure :ignored_exception_messages => {klass => 'oo'}
              Squash::Ruby.should_not_receive(:http_transmit)
              Squash::Ruby.notify(@exception).should be_false
            end
          end
        end
      end

      it "should return true if the exception is ignored because of the ignored-exception-messages configuration (regexp)" do
        Squash::Ruby.configure :ignored_exception_messages => {'ArgumentError' => /oo/}
        Squash::Ruby.should_not_receive(:http_transmit)
        Squash::Ruby.notify(@exception).should be_false
      end

      it "should return true if the exception is ignored because of the ignored-exception-procs configuration" do
        Squash::Ruby.configure :ignored_exception_procs => lambda { |error, user_data| error.kind_of?(ArgumentError) && user_data[:foo] == 'bar' }

        Squash::Ruby.should_receive(:http_transmit).once
        Squash::Ruby.notify(@exception, :foo => 'bar').should be_false
        Squash::Ruby.notify(@exception, :foo => 'baz').should be_true
      end
    end

    context "[check_user_data]" do
      it "should raise an error if the user data contains :bt" do
        Squash::Ruby.should_receive(:failsafe_handler).with do |_, error|
          error.to_s.include? 'bt'
        end
        Squash::Ruby.notify @exception, :bt => 'foo'
      end

      it "should raise an error if the user data contains :mesg" do
        Squash::Ruby.should_receive(:failsafe_handler).with do |_, error|
          error.to_s.include? 'mesg'
        end
        Squash::Ruby.notify @exception, :mesg => 'foo'
      end
    end

    describe "[valueify]" do
      before(:each) { Squash::Ruby.configure :disable_failsafe => true }

      it "should convert variables to complex value hashes" do
        yaml = (defined?(JRuby) && RUBY_VERSION >= '1.9.0') ? "--- !ruby/regexp '/Hello, world!/'\n" : "--- !ruby/regexp /Hello, world!/\n"
        yaml << "...\n" if RUBY_VERSION >= '1.9.0' && !defined?(JRuby)
        Squash::Ruby.valueify(/Hello, world!/).should eql("language"   => "ruby",
                                                          "inspect"    => "/Hello, world!/",
                                                          "yaml"       => yaml,
                                                          "class_name" => "Regexp",
                                                          "json"       => "\"(?-mix:Hello, world!)\"",
                                                          "to_s"       => "(?-mix:Hello, world!)")
      end

      it "should not convert JSON primitives" do
        Squash::Ruby.valueify("hello").should eql("hello")
        Squash::Ruby.valueify(true).should eql(true)
        Squash::Ruby.valueify(false).should eql(false)
        Squash::Ruby.valueify(nil).should eql(nil)
      end

      it "should filter values" do
        Squash::Ruby.stub!(:value_filter).and_return('foo' => 'bar')
        tos  = (RUBY_VERSION < '1.9.0') ? "foobar" : '{"foo"=>"bar"}'
        yaml = (RUBY_VERSION < '1.9.0') ? "--- \nfoo: bar\n" : "---\nfoo: bar\n"
        Squash::Ruby.valueify("hello" => "world").should eql({
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
        Squash::Ruby.valueify(obj)['to_json'].should be_nil
      end

      it "should gracefully recover from exceptions raised when calling #to_yaml" do
        obj = Object.new
        class << obj
          def to_yaml() raise ArgumentError, "oops!"; end
        end
        Squash::Ruby.valueify(obj)['to_yaml'].should be_nil
      end

      it "should gracefully recover from exceptions raised when calling #inspect" do
        obj = Object.new
        class << obj
          def inspect() raise ArgumentError, "oops!"; end
        end
        Squash::Ruby.valueify(obj)['inspect'].should eql("[ArgumentError: oops! raised when calling #inspect]")
      end

      it "should gracefully recover from exceptions raised when calling #to_s" do
        obj = Object.new
        class << obj
          def to_s() raise ArgumentError, "oops!"; end
        end
        Squash::Ruby.valueify(obj)['to_s'].should eql("[ArgumentError: oops! raised when calling #to_s]")
      end
    end

    context "[http_transmit]" do
      before(:each) do
        Squash::Ruby.configure :api_host         => 'https://squash.example.com',
                               :transmit_timeout => 15,
                               :disable_failsafe => true
      end

      it "should transmit to the API endpoint" do
        http = mock('Net:HTTP')
        http.should_receive(:request).with do |req|
          req.path == '/api/1.0/notify' &&
              req.body.size > 0
        end.and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = mock('Net::HTTP')
        Net::HTTP.should_receive(:new).once.with('squash.example.com', 443).and_return(mock)
        mock.should_receive(:open_timeout=).once.with(15)
        mock.should_receive(:read_timeout=).once.with(15)
        mock.stub!(:use_ssl=)
        mock.should_receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception
      end

      it "should support the http_proxy environment variable" do
        Squash::Ruby.configure :api_host => 'http://squash.example.com'

        http_proxy        = ENV['http_proxy']
        ENV['http_proxy'] = 'proxy.example.com'

        http = mock('Net:HTTP')
        http.should_receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = mock('Net::HTTP')
        Net::HTTP.should_receive(:Proxy).once.with('proxy.example.com', 80, nil, nil).and_return(Net::HTTP)
        Net::HTTP.stub!(:new).and_return(mock)
        mock.stub!(:open_timeout=)
        mock.stub!(:read_timeout=)
        mock.stub!(:use_ssl=)
        mock.should_receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['http_proxy'] = http_proxy
      end

      it "should support the https_proxy environment variable" do
        Squash::Ruby.configure :api_host => 'https://squash.example.com'

        http_proxy         = ENV['https_proxy']
        ENV['https_proxy'] = 'proxy.example.com'

        http = mock('Net:HTTP')
        http.should_receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = mock('Net::HTTP')
        Net::HTTP.should_receive(:Proxy).once.with('proxy.example.com', 443, nil, nil).and_return(Net::HTTP)
        Net::HTTP.stub!(:new).and_return(mock)
        mock.stub!(:open_timeout=)
        mock.stub!(:read_timeout=)
        mock.stub!(:use_ssl=)
        mock.should_receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['https_proxy'] = http_proxy
      end

      it "should support the no_proxy environment variable" do
        Squash::Ruby.configure :api_host => 'http://squash.example.com'

        http_proxy        = ENV['http_proxy']
        no_proxy          = ENV['no_proxy']
        ENV['http_proxy'] = 'proxy.example.com'
        ENV['no_proxy']   = '.example.com,.foo.com'

        http = mock('Net:HTTP')
        http.should_receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = mock('Net::HTTP')
        Net::HTTP.should_not_receive(:Proxy)
        Net::HTTP.should_receive(:new).once.and_return(mock)
        mock.stub!(:open_timeout=)
        mock.stub!(:read_timeout=)
        mock.stub!(:use_ssl=)
        mock.should_receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['http_proxy'] = http_proxy
        ENV['no_proxy']   = no_proxy
      end

      it "should ignore inapplicable no_proxy values" do
        Squash::Ruby.configure :api_host => 'http://squash.example.com'

        http_proxy        = ENV['http_proxy']
        no_proxy          = ENV['no_proxy']
        ENV['http_proxy'] = 'proxy.example.com'
        ENV['no_proxy']   = '.foo.com,.bar.com'

        http = mock('Net:HTTP')
        http.should_receive(:request).and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

        mock = mock('Net::HTTP')
        Net::HTTP.should_receive(:Proxy).once.with('proxy.example.com', 80, nil, nil).and_return(Net::HTTP)
        Net::HTTP.stub!(:new).and_return(mock)
        mock.stub!(:open_timeout=)
        mock.stub!(:read_timeout=)
        mock.stub!(:use_ssl=)
        mock.should_receive(:start).once.and_yield(http)

        Squash::Ruby.notify @exception

        ENV['http_proxy'] = http_proxy
        ENV['no_proxy']   = no_proxy
      end

      context "[request body]" do
        before :each do
          @exception.send :instance_variable_set, :@custom_ivar, 'foobar'

          http = mock('Net:HTTP')
          http.should_receive(:request) do |req|
            @body = req.body
            Net::HTTPSuccess.new('1.1', 200, 'OK')
          end

          mock = mock('Net::HTTP')
          Net::HTTP.stub!(:new).and_return(mock)
          mock.stub!(:start).and_yield(http)
          mock.stub!(:open_timeout=)
          mock.stub!(:read_timeout=)
          mock.stub!(:use_ssl=)

          Squash::Ruby.notify @exception, :custom_data => 'barfoo'
          @json = JSON.parse(@body)
        end

        it "should transmit information about the exception" do
          @json.should include('class_name')
          @json.should include('message')
          @json.should include('backtraces')
          @json.should include('occurred_at')
          @json.should include('revision')

          @json['environment'].should eql('test')
          @json['client'].should eql('ruby')
        end

        it "should properly tokenize and normalize backtraces" do
          bt = if @exception.respond_to?(:_squash_bindings_stack)
                 @exception._squash_bindings_stack
               else
                 @exception.backtrace.reject { |line| line.include?('.java') }
               end
          serialized = @json['backtraces'].first['backtrace'].reject { |elem| elem['type'] }
          serialized.zip(bt).each do |(serialized_element, bt_element)|
            bt_element = bt_element.eval('caller(0, 1)[0]') if bt_element.kind_of?(Binding)
            file, line, method = bt_element.split(':')
            file.sub! /^#{Regexp.escape Dir.getwd}\//, ''

            serialized_element['file'].should eql(file)
            serialized_element['line'].should eql(line.to_i)
            serialized_element['symbol'].should eql(method ? method.match(/in `(.+)'$/)[1] : nil)
          end
        end

        it "should transmit information about the environment" do
          @json.should include('pid')
          @json.should include('hostname')
          @json['env_vars'].should eql(ENV.to_hash)
          @json.should include('arguments')
        end

        it "should transmit the user data" do
          @json['user_data'].should include('custom_data')
        end

        it "should transmit the exception instance variables" do
          @json['ivars'].should include('custom_ivar')
        end
      end
    end

    context "[failsafe_handler]" do
      before(:each) do
        Squash::Ruby.stub!(:http_transmit).and_raise(Net::HTTPError.new("File Not Found", 404))
      end

      after(:each) { FileUtils.rm_f 'squash.failsafe.log' }

      it "should log failsafe errors to the failsafe log" do
        Squash::Ruby.notify @exception
        File.read('squash.failsafe.log').should include('Net::HTTPError')
        File.read('squash.failsafe.log').should include('Sploops!')
      end

      it "should raise failsafe errors if the failsafe handler is disabled" do
        Squash::Ruby.configure :disable_failsafe => true
        lambda { Squash::Ruby.notify @exception }.should raise_error(Net::HTTPError)
        File.exist?('squash.failsafe.log').should be_false
      end

      it "should log failsafe errors to stderr if it can't log to disk" do
        File.stub!(:open).and_raise(Errno::EISDIR)
        stderr = []
        $stderr.stub!(:puts) { |out| stderr << out }
        Squash::Ruby.notify @exception
        File.exist?('squash.failsafe.log').should be_false
        stderr.should include("Couldn't write to failsafe log (Is a directory); writing to stderr instead.")
      end
    end

    context "[special backtraces]" do
      before :each do
        http = mock('Net:HTTP')
        http.should_receive(:request) do |req|
          @body = req.body
          Net::HTTPSuccess.new('1.1', 200, 'OK')
        end

        mock = mock('Net::HTTP')
        Net::HTTP.stub!(:new).and_return(mock)
        mock.stub!(:start).and_yield(http)
        mock.stub!(:open_timeout=)
        mock.stub!(:read_timeout=)
        mock.stub!(:use_ssl=)
      end

      it "should properly tokenize JRuby Java backtraces (form 1)" do
        ::JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["arjdbc/jdbc/RubyJdbcConnection.java:191:in `execute'"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
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
        @exception.stub!(:backtrace).and_return(
            ["     instance_exec at org/jruby/RubyBasicObject.java:1757"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
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
        @exception.stub!(:backtrace).and_return(
            ["org.jruby.RubyHash$27.visit(RubyHash.java:1646)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
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
        @exception.stub!(:backtrace).and_return(
            ["  sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
                                                     "faulted"   => true,
                                                     "backtrace" =>
                                                         [{"type"   => "java_native",
                                                           "symbol" => "invoke0",
                                                           "class"  => "sun.reflect.NativeMethodAccessorImpl"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (ASM invoker)" do
        JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["  org.jruby.RubyKernel$INVOKER$s$send19.call(RubyKernel$INVOKER$s$send19.gen)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
                                                     "faulted"   => true,
                                                     "backtrace" =>
                                                         [{"type" => "asm_invoker",
                                                           "file" => "send19.gen"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 1)" do
        JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["  rubyjit.ActionController::Rendering$$process_action_7EA12C1BF98F2835D4AE1311F8A1D948CBFB87DA.__file__(vendor/bundle/jruby/1.9/gems/actionpack-3.2.12/lib/action_controller/metal/rendering.rb:10)",
             "  rubyjit.ActiveSupport::TaggedLogging$$tagged!_2790A33722B3CBEBECECCFF90F769EB0F50B6FF2.chained_0_ensure_1$RUBY$__ensure__(vendor/bundle/jruby/1.9/gems/activesupport-3.2.12/lib/active_support/tagged_logging.rb:22)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
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
        @exception.stub!(:backtrace).and_return(
            ["  rubyjit$AbstractController::Callbacks$$process_action!_9E31DE6CC20BF4BD4675A39AC9F969A1DDA08377$block_0$RUBY$__file__.call(rubyjit$AbstractController::Callbacks$$process_action_9E31DE6CC20BF4BD4675A39AC9F969A1DDA08377$block_0$RUBY$__file__)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
                                                     "faulted"   => true,
                                                     "backtrace" =>
                                                         [{'type'   => 'jruby_block',
                                                           "class"  => "AbstractController::Callbacks",
                                                           "symbol" => "process_action!"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 3)" do
        JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["  rubyjit.Squash::Ruby::ControllerMethods$$_squash_around_filter!_84CA00BB277BFC0F702CBE86BC4897E3CE15B5AA.chained_0_rescue_1$RUBY$SYNTHETIC__file__(vendor/bundle/jruby/1.9/gems/squash_rails-1.1.0/lib/squash/ruby/controller_methods.rb:138)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
                                                     "faulted"   => true,
                                                     "backtrace" =>
                                                         [{"file"   => "vendor/bundle/jruby/1.9/gems/squash_rails-1.1.0/lib/squash/ruby/controller_methods.rb",
                                                           "line"   => 138,
                                                           "symbol" => "Squash::Ruby::ControllerMethods#_squash_around_filter!"}]}])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Ruby backtraces (special form 4)" do
        JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["  rubyjit.ActionController::ImplicitRender$$send_action_9AF6F8FC466F72ECECBF8347A4DDB47F06FB9E8F.__file__(vendor/bundle/jruby/1.9/gems/actionpack-3.2.12/lib/action_controller/metal/implicit_render.rb)",
             "  rubyjit.ActiveSupport::Notifications::Instrumenter$$instrument!_2E2DDD0482328008F39B59E6DE8E25217A389086.chained_0_ensure_1$RUBY$__ensure__(vendor/bundle/jruby/1.9/gems/activesupport-3.2.12/lib/active_support/notifications/instrumenter.rb)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([{"name"      => "Active Thread/Fiber",
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
      lambda { Squash::Ruby.ignore_exceptions }.should raise_error(ArgumentError)
    end

    it "should not report any exceptions if not called with any arguments" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions do
          raise ArgumentError, "sploops"
        end
      rescue => err
        err.send(:instance_variable_get, :@_squash_do_not_report).should be_true
        raised = true
      end
      raised.should be_true
    end

    it "should not report exceptions of the given classes" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions(RangeError) do
          raise RangeError, "sploops"
        end
      rescue RangeError => err
        err.send(:instance_variable_get, :@_squash_do_not_report).should be_true
        raised = true
      end
      raised.should be_true
    end

    it "should report exceptions that are superclasses of the given classes" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions(RangeError) do
          raise "sploops"
        end
      rescue StandardError => err
        err.send(:instance_variable_get, :@_squash_do_not_report).should be_false
        raised = true
      end
      raised.should be_true
    end

    it "should not report exceptions that are subclasses of the given classes" do
      raised = false
      begin
        Squash::Ruby.ignore_exceptions(RangeError) do
          raise FloatDomainError, "sploops"
        end
      rescue StandardError => err
        err.send(:instance_variable_get, :@_squash_do_not_report).should be_nil
        raised = true
      end
      raised.should be_true
    end
  end

  describe '.add_user_data' do
    it "should raise an error if not passed a block" do
      lambda { Squash::Ruby.add_user_data(:foo => 'bar') }.should raise_error(ArgumentError)
    end

    context "[check_user_data]" do
      it "should raise an error if the user data contains :bt" do
        lambda { Squash::Ruby.add_user_data(:bt => 'bar') { 1 } }.should raise_error(ArgumentError)
      end

      it "should raise an error if the user data contains :mesg" do
        lambda { Squash::Ruby.add_user_data(:mesg => 'bar') { 1 } }.should raise_error(ArgumentError)
      end
    end

    it "should add the user data to an exception raised in the block" do
      raised = false
      begin
        Squash::Ruby.add_user_data(:new_data => 'baz') do
          raise "sploops"
        end
      rescue StandardError => err
        err.send(:instance_variable_get, :@new_data).should eql('baz')
        raised = true
      end
      raised.should be_true
    end
  end

  describe '.fail_silently' do
    it "should raise an error if not passed a block" do
      lambda { Squash::Ruby.fail_silently }.should raise_error(ArgumentError)
    end

    it "should report but not raise any exceptions if called with no arguments" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(ArgumentError), {})
      lambda do
        Squash::Ruby.fail_silently { raise ArgumentError, "sploops" }
      end.should_not raise_error
    end

    it "should report but not raise any exceptions if called with only options" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(ArgumentError), :foo => 'bar')
      lambda do
        Squash::Ruby.fail_silently(:foo => 'bar') { raise ArgumentError, "sploops" }
      end.should_not raise_error
    end

    it "should only suppress exceptions of the given classes" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(RangeError), {})
      lambda do
        Squash::Ruby.fail_silently(RangeError) { raise RangeError, "sploops" }
      end.should_not raise_error

      Squash::Ruby.should_not_receive(:notify)
      lambda do
        Squash::Ruby.fail_silently(RangeError) { raise ArgumentError, "sploops" }
      end.should raise_error
    end

    it "should allow options" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(RangeError), :foo => 'bar')
      lambda do
        Squash::Ruby.fail_silently(RangeError, :foo => 'bar') { raise RangeError, "sploops" }
      end.should_not raise_error
    end

    it "should not suppress exceptions that are superclasses of the given classes" do
      Squash::Ruby.should_not_receive(:notify)
      lambda do
        Squash::Ruby.fail_silently(RangeError) { raise "sploops" }
      end.should raise_error
    end

    it "should suppress exceptions that are subclasses of the given classes" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(FloatDomainError), {})
      lambda do
        Squash::Ruby.fail_silently(RangeError) { raise FloatDomainError, "sploops" }
      end.should_not raise_error
    end
  end

  describe '.configure' do
    it "should set configuration values" do
      Squash::Ruby.configure :custom => 'config'
      Squash::Ruby.send(:configuration, :custom).should eql('config')
    end

    it "should allow string and symbol values" do
      Squash::Ruby.configure 'custom' => 'config'
      Squash::Ruby.send(:configuration, :custom).should eql('config')
    end

    it "should merge new values in with existing values" do
      Squash::Ruby.configure :custom => 'config', :custom2 => 'config2'
      Squash::Ruby.configure :custom => 'confignew', :custom3 => 'config3'
      Squash::Ruby.send(:configuration, :custom).should eql('confignew')
      Squash::Ruby.send(:configuration, :custom2).should eql('config2')
      Squash::Ruby.send(:configuration, :custom3).should eql('config3')
    end
  end

  describe ".notify_deploy" do
    it "should do nothing if Squash is disabled" do
      Squash::Ruby.configure :disabled => true
      Squash::Ruby.should_not_receive :http_transmit
      Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
    end

    it "should POST a notification to the deploy endpoint" do
      http = mock('HTTP')
      http.should_receive(:request).once.with do |request|
        JSON.parse(request.body).should eql(
                                            'project'     => {'api_key' => 'foobar'},
                                            'environment' => {'name' => 'development'},
                                            'deploy'      => {
                                                'deployed_at' => Time.now.to_s,
                                                'revision'    => 'abc123',
                                                'hostname'    => 'myhost.local'
                                            }
                                        )
      end.and_return(Net::HTTPSuccess.new('1.1', 200, 'OK'))

      mock = mock('Net::HTTP')
      Net::HTTP.should_receive(:new).once.with('test.host', 80).and_return(mock)
      mock.should_receive(:use_ssl=).once.with(false)
      mock.stub!(:open_timeout=)
      mock.stub!(:read_timeout=)
      mock.should_receive(:start).once.and_yield(http)

      Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
    end

    it "should report an error given a bad response" do
      http = mock('HTTP')
      http.stub!(:request).and_return(Net::HTTPNotFound.new('1.1', 404, 'Not Found'))

      mock = mock('Net::HTTP')
      Net::HTTP.should_receive(:new).once.with('test.host', 80).and_return(mock)
      mock.should_receive(:use_ssl=).once.with(false)
      mock.stub!(:open_timeout=)
      mock.stub!(:read_timeout=)
      mock.should_receive(:start).once.and_yield(http)

      $stderr.should_receive(:puts).once.with(/\[Squash\] Bad response/)
      Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
      FileUtils.rm 'squash.failsafe.log'
    end
  end

  it "should report a timeout to stderr" do
    http = mock('HTTP')
    http.stub!(:request).and_raise(Timeout::Error)

    mock = mock('Net::HTTP')
    Net::HTTP.should_receive(:new).once.with('test.host', 80).and_return(mock)
    mock.should_receive(:use_ssl=).once.with(false)
    mock.stub!(:open_timeout=)
    mock.stub!(:read_timeout=)
    mock.should_receive(:start).once.and_yield(http)

    $stderr.should_receive(:puts).once.with(/\[Squash\] Timeout/)
    Squash::Ruby.notify_deploy 'development', 'abc123', 'myhost.local'
  end

  describe ".record" do
    it "should accept an exception class, message, and options" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(ArgumentError), :foo => 'bar') do |exc, *other|
        exc.to_s.should eql('foobar')
      end
      Squash::Ruby.record ArgumentError, "foobar", :foo => 'bar'
    end

    it "should accept an exception class and message" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(ArgumentError), {}) do |exc, *other|
        exc.to_s.should eql('foobar')
      end
      Squash::Ruby.record ArgumentError, "foobar"
    end

    it "should accept a message and options" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(StandardError), :foo => 'bar') do |exc, *other|
        exc.to_s.should eql('foobar')
      end
      Squash::Ruby.record "foobar", :foo => 'bar'
    end

    it "should accept a message" do
      Squash::Ruby.should_receive(:notify).once.with(an_instance_of(StandardError), {}) do |exc, *other|
        exc.to_s.should eql('foobar')
      end
      Squash::Ruby.record "foobar"
    end
  end

  describe ".current_revision" do
    before :each do
      FakeFS.activate!
      FakeFS::FileSystem.clear
    end
    after(:each) { FakeFS.deactivate! }

    context "[revision file specified]" do
      it "should return the contents of the revision file" do
        File.open('test_file', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        Squash::Ruby.configure :revision_file => 'test_file'
        Squash::Ruby.current_revision.should eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should raise an exception for an improperly-formatted revision file" do
        File.open('test_file', 'w') { |f| f.puts 'halp!' }
        Squash::Ruby.configure :revision_file => 'test_file'
        lambda { Squash::Ruby.current_revision }.should raise_error(/Unknown Git revision/)
      end
    end

    context "[revision specified]" do
      it "should return the revision" do
        Squash::Ruby.configure :revision      => 'cb586586d2882ebfb5e892c8fc558ada8d2faf95',
                               :revision_file => 'test_file'
        Squash::Ruby.current_revision.should eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should raise an exception for an improperly-formatted revision" do
        Squash::Ruby.configure :revision => 'hello'
        lambda { Squash::Ruby.current_revision }.should raise_error(/Unknown Git revision/)
      end
    end

    context "[no revision file specified]" do
      it "should return the HEAD if it is a commit" do
        FileUtils.mkdir_p '.git'
        File.open('.git/HEAD', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        Squash::Ruby.current_revision.should eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should return the contents of the ref file if HEAD is a ref" do
        FileUtils.mkdir_p '.git/refs/heads'
        File.open('.git/HEAD', 'w') { |f| f.puts 'ref: refs/heads/branch' }
        File.open('.git/refs/heads/branch', 'w') { |f| f.puts 'cb586586d2882ebfb5e892c8fc558ada8d2faf95' }
        Squash::Ruby.current_revision.should eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
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
        Squash::Ruby.current_revision.should eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should use `git rev-parse` otherwise" do
        FileUtils.mkdir_p '.git'
        File.open('.git/HEAD', 'w') { |f| f.puts 'ref: refs/heads/unknown' }
        Squash::Ruby.should_receive(:`).once.with('git rev-parse refs/heads/unknown').and_return('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
        Squash::Ruby.current_revision.should eql('cb586586d2882ebfb5e892c8fc558ada8d2faf95')
      end

      it "should raise an exception if not running in a Git repo" do
        lambda { Squash::Ruby.current_revision }.should raise_error(/You must set the :revision_file configuration/)
      end
    end
  end
end
