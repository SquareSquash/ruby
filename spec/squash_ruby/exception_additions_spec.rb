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

require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'squash/ruby/exception_additions'

describe Exception do
  describe ".new" do
    it "should behave like the original method" do
      e = Exception.new("Hello!")
      expect(e).to be_kind_of(Exception)
      expect(e.to_s).to eql("Hello!")
    end

    it "should accept user data" do
      e = Exception.new("Hello!", :foo => 'bar')
      expect(e).to be_kind_of(Exception)
      expect(e.to_s).to eql("Hello!")
      expect(e.send(:instance_variable_get, :@foo)).to eql('bar')
    end

    it "should not accept the :bt key" do
      expect { Exception.new 'foo', :bt => 'bar' }.to raise_error(ArgumentError)
    end

    it "should not accept the :mesg key" do
      expect { Exception.new 'foo', :mesg => 'bar' }.to raise_error(ArgumentError)
    end
  end

  describe "#user_data" do
    before :each do
      @exception = Exception.new("Hello!")
    end

    it "should set user data" do
      @exception.user_data(:foo => 'bar')
      expect(@exception.send(:instance_variable_get, :@foo)).to eql('bar')
    end

    it "should not accept the :bt key" do
      expect { @exception.user_data :bt => 'bar' }.to raise_error(ArgumentError)
    end

    it "should not accept the :mesg key" do
      expect { @exception.user_data :mesg => 'bar' }.to raise_error(ArgumentError)
    end
  end
end
