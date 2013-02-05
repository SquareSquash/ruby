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

# Reopens the `Exception` class to add a convenient way of appending user data
# to an exception at the time of the raise.
#
# @example
#   raise ArgumentError.new("value must be a number", :value => value) unless value.kind_of?(Fixnum)

class Exception

  # @overload new(message, user_data={})
  #   Creates a new exception instance, optionally with user data.
  #   @param [String] message The exception message.
  #   @param [Hash] user_data Additional data to report to Squash about the
  #     exception.
  #   @return [Exception] The initialized exception.
  #   @raise [ArgumentError] If `data` contains the keys `mesg` or `bt`.

  def self.new(*args)
    user_data = if args.last.is_a?(Hash)
                  args.pop
                else
                  {}
                end
    super(*args).user_data(user_data)
  end

  # Annotates this exception with user data. Merges in any new data with
  # existing user data.
  #
  # @param [Hash] data The user data to add.
  # @return [Exception] The receiver.
  # @raise [ArgumentError] If `data` contains the keys `mesg` or `bt`.

  def user_data(data)
    Squash::Ruby.check_user_data data
    data.each do |ivar, value|
      instance_variable_set :"@#{ivar}", value
    end
    self
  end
end
