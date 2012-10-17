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

require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'squash/ruby/exception_additions'

describe Exception do
  describe ".new" do
    it "should behave like the original method" do
      e = Exception.new("Hello!")
      e.should be_kind_of(Exception)
      e.to_s.should eql("Hello!")
    end

    it "should accept user data" do
      e = Exception.new("Hello!", :foo => 'bar')
      e.should be_kind_of(Exception)
      e.to_s.should eql("Hello!")
      e.send(:instance_variable_get, :@foo).should eql('bar')
    end

    it "should not accept the :bt key" do
      lambda { Exception.new 'foo', :bt => 'bar' }.should raise_error(ArgumentError)
    end

    it "should not accept the :mesg key" do
      lambda { Exception.new 'foo', :mesg => 'bar' }.should raise_error(ArgumentError)
    end
  end

  describe "#user_data" do
    before :each do
      @exception = Exception.new("Hello!")
    end

    it "should set user data" do
      @exception.user_data(:foo => 'bar')
      @exception.send(:instance_variable_get, :@foo).should eql('bar')
    end

    it "should not accept the :bt key" do
      lambda { @exception.user_data :bt => 'bar' }.should raise_error(ArgumentError)
    end

    it "should not accept the :mesg key" do
      lambda { @exception.user_data :mesg => 'bar' }.should raise_error(ArgumentError)
    end
  end
end
