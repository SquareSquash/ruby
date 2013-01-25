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
        result = Squash::Ruby.valueify(/Hello, world!/)

        yaml_result = result.delete('yaml')

        if RUBY_VERSION =~ /^1.8/
          yaml_result.should eql "--- !ruby/regexp /Hello, world!/\n"
        else
          if defined?(JRuby)
            yaml_result.should eql "--- !ruby/regexp '/Hello, world!/'\n"
          else
            yaml_result.should eql "--- !ruby/regexp /Hello, world!/\n...\n"
          end
        end

        result.should eql("language"   => "ruby",
                          "inspect"    => "/Hello, world!/",
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
        result = Squash::Ruby.valueify("hello" => "world")

        yaml_result = result.delete('yaml')
        to_s_result = result.delete('to_s')

        if RUBY_VERSION =~ /^1.8/
          yaml_result.should eql "--- \nfoo: bar\n"
          to_s_result.should eql "foobar"
        else
          yaml_result.should eql "---\nfoo: bar\n"
          to_s_result.should eql "{\"foo\"=>\"bar\"}"
        end

        result.should eql({
            "inspect"=>"{\"foo\"=>\"bar\"}",
            "json"=>"{\"foo\":\"bar\"}",
            "language"=>"ruby",
            "class_name"=>"Hash"})
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
          if defined?(JRuby)
            @json['backtraces'].first[2].should eql(@exception.backtrace.map do |element|
              result = []
              file, line, method = element.split(':')
              if file =~ /org\/jruby/ # jruby built-in file
                result << '_JAVA_'
                result << file.gsub('org/jruby/', '')
              else # project file, strip out project dir from path
                result << file.gsub("#{Dir.getwd}/", '')
              end
              result << line.to_i
              result << if method # normalized method name
                method.gsub(/in `(.+)'$/, '\1')
              end
              if file =~ /\.java$/ # add fully qualified Java class name
                result << file.gsub('/', '.').gsub('.java', '')
              end
              result
            end)
          else
            @json['backtraces'].first[2].should eql(@exception.backtrace.map do |element|
              file, line, method = element.split(':')
              file.sub! /^#{Regexp.escape Dir.getwd}\//, ''
              [file, line.to_i, method ? method.match(/in `(.+)'$/)[1] : nil]
            end)
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
        JSON.parse(@body)['backtraces'].should eql([
                                                       ['Active Thread/Fiber', true, [
                                                           ['_JAVA_', 'RubyJdbcConnection.java', 191, 'execute', 'arjdbc.jdbc.RubyJdbcConnection']
                                                       ]]
                                                   ])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (form 2)" do
        ::JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["     instance_exec at org/jruby/RubyBasicObject.java:1757"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([
                                                       ['Active Thread/Fiber', true, [
                                                           ['_JAVA_', 'RubyBasicObject.java', 1757, 'instance_exec', 'org.jruby.RubyBasicObject']
                                                       ]]
                                                   ])
        Object.send(:remove_const, :JRuby)
      end

      it "should properly tokenize JRuby Java backtraces (form 3)" do
        JRuby = Object.new
        @exception.stub!(:backtrace).and_return(
            ["org.jruby.RubyHash$27.visit(RubyHash.java:1646)"]
        )
        Squash::Ruby.notify @exception
        JSON.parse(@body)['backtraces'].should eql([
                                                       ['Active Thread/Fiber', true, [
                                                           ['_JAVA_', 'RubyHash.java', 1646, 'visit', 'org.jruby.RubyHash$27']
                                                       ]]
                                                   ])
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

    it "should not exceptions that are superclasses of the given classes" do
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
