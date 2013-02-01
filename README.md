Squash Client Library: Ruby
===========================

This client library reports exceptions to Squash, the Squarish exception
reporting and management system.

[![Build Status](https://travis-ci.org/SquareSquash/ruby.png)](https://travis-ci.org/SquareSquash/ruby)

Documentation
-------------

Comprehensive documentation is written in YARD- and Markdown-formatted comments
throughout the source. To view this documentation as an HTML site, run
`rake doc`.

For an overview of the various components of Squash, see the website
documentation at https://github.com/SquareSquash/web.

Compatibility
-------------

This library is compatible with Ruby 1.8.6 and later, including Ruby Enterprise
Edition.

Requirements
------------

The only dependency is the `json` gem (http://rubygems.org/gems/json). You can use
any JSON gem that conforms to the typical standard (`require 'json';
object.to_json`).

Usage
-----

Add the Squash client to your Gemfile with
`gem 'squash_ruby', :require => 'squash/ruby'`. Before you can use Squash, you
must configure it (see **Configuration** below). At a minimum, you must specify
the API host and which project you are recording exceptions for:

```` ruby
Squash::Ruby.configure :api_key => 'YOUR_API_KEY',
                       :api_host => 'https://your.squash.host',
                       :environment => 'production'
````

To use Squash to manage your exceptions, place a `begin::rescue` statement at
the highest level of your code. Inside the `rescue` block, make a call to
{Squash::Ruby.notify} with the exception. In general, you probably want to
rescue all subclasses of `Object`, so you catch every possible exception.
Example:

```` ruby
begin
  all_of_your_code
rescue Object => err
  Squash::Ruby.notify err
  raise
end
````

In this example the exception is re-raised to take advantage of Ruby's typical
last-resort exception handling as well.

There are many additional features you can take advantage of; see **Additional
Features** below.

### Additional Features

There are a number of other features you can take advantage of to help you debug
your exceptions:

#### User Data

Exceptions can be annotated with freeform user data. This data can take any
format and have any meaning, typically being relevant to the exception at hand.
This is in fact the system that `squash_rails` uses to annotate an exception
with information about the Rails request.

There are multiple ways to add user data to an exception. By default, user data
is culled from any instance variables set in the exception. This means that for
those exceptions that store additional information in instance variables, you
get user data "for free." An example is the `ActiveRecord::RecordInvalid`
exception, which stores the invalid record as an instance variable.

You can also add user data using the {Squash::Ruby.add_user_data} method:

```` ruby
input = gets
Squash::Ruby.add_user_data(:input => input) do
  process_input # may raise an exception
end
````

And lastly, if you require `squash/ruby/exception_additions`, you can add user
data directly in the exception constructor:

```` ruby
require 'squash/ruby/exception_additions'

def process_value(value)
  raise ArgumentError.new("value must be a number", :value => value) unless value.kind_of?(Fixnum)
  # [...]
end
````

Requiring that file also lets you add user data to exceptions you catch and
re-raise:

```` ruby
require 'squash/ruby/exception_additions'

begin
  do_something_with_input(input)
rescue ArgumentError => err
  err.user_data :input => input
  raise # assumed that Squash::Ruby.notify is called somewhere further up in the stack
end
````

If monkey-patching doesn't appeal to you, then don't load
`squash/ruby/exception_additions`; it's not required for the client to work.

#### Ignoring Exceptions

You can ignore certain exceptions within a block of code if those exceptions are
not worth sending to Squash. Use the {Squash::Ruby.ignore_exceptions} method:

```` ruby
Squash::Ruby.ignore_exceptions(SocketError, Net::HTTPError) do
  some_http_code_that_could_fail
end
````

The exceptions _will_ be raised (not eaten) but will _not_ be reported to
Squash.

You can also globally ignore exceptions using the `ignored_exceptions`
configuration; see **Configuration** below.

Configuration
-------------

You can configure the client with the {Squash::Ruby.configure} method. Calling
this method multiple times will merge new values in with the existing
configuration. The method takes a hash, which accepts the following (symbol)
keys:

### General

* `disabled`: If `true`, the Squash client will not report any errors.
* `api_key`: The API key of the project that exceptions will be associated with.
  This configuration option is required. The value can be found by going to the
  project's home page on Squash.
* `environment`: The environment that exceptions will be associated with.
* `project_root`: The path to your project's root directory. This path will be
  stripped from backtrace lines. By default it's set to the working directory.

### Revision Information

Squash can determine the current code revision using one of two methods. Specify
only one of the following configuration keys:

* `revision_file`: The path to a file storing the SHA1 of the current Git
  revision. This is the revision of the code that is currently running.
* `revision`: The 40-character SHA1 of the current deployed revision.
* `repository_root`: The path to the working directory of the Git repository
  that is currently running. Use this option if your deployed code is a working
  Git repository.

By default, `repository_root` is assumed and is set to `Dir.getwd`. Other
options override `repository_root`.

### Error Transmission

* `api_host`: The host on which Squash is running. This field is required.
* `notify_path`: The path to post new exception notifications to. By default
  it's set to `/api/1.0/notify`.
* `transmit_timeout`: The amount of time to wait before giving up on trasmitting
  an error. By default this is treated as both an open and a read timeout.

### Ignored Exceptions

* `ignored_exception_classes`: An array of exception class names that will not
  be reported to Squash.
* `ignored_exception_messages`: A hash mapping an exception class name to an
  array of regexes. Exceptions of that class whose messages match a regex in the
  list will not be reported to Squash.
* `ignored_exception_procs`: An array of `Proc` objects that can be used to
  filter exceptions. Takes as arguments 1) the exception and 2) the user data
  hash. Should return `true` if the exception should be ignored (_not_ reported)
  and false otherwise. The user data hash can include stuff useful to extended
  client libraries (e.g., Squash Rails client); an example:

```` ruby
Squash::Ruby.configure :ignored_exception_procs => lambda do |exception, user_data|
  exception.kind_of?(ActiveRecord::RecordNotFound) && user_data[:headers]['X-Testing'].blank?
end
````

### Failsafe Reporting

* `failsafe_log`: The pathname of a log file where failsafe exceptions will be
  recorded (see **Failsafe Reporting** below). By default, records to a file
  named `squash.failsafe.log` in the current working directory.
* `disable_failsafe`: If `true`, the failsafe handler will be disabled.
  Exceptions raised when Squash is processing another exception will be handled
  normally by the Ruby interpreter.

Error Transmission
------------------

Exceptions are transmitted to Squash using JSON-over-HTTPS. A default API
endpoint is pre-configured, though you can always set your own (see
**Configuration** above).

By default, `Net::HTTP` is used to transmit errors to the API server. If you
would prefer to use your own HTTP library, you can override the
{Squash::Ruby.http_transmit} method. This method is also used for deploy
notification.

Failsafe Reporting
------------------

In the event that the Squash client itself raises an exception when processing
an exception, it will log that exception to the failsafe log. (See the
`failsafe_log` configuration option, described above.) Both the original
exception and the failsafe error will be logged. The original exception will
still be re-raised, but the failsafe error will be "eaten."

If for some reason the exceptions cannot be logged (e.g., a permissions error),
they will be logged to standard error.

It would behoove the engineers of a project using Squash to periodically check
the failsafe log, as it may contain exceptions that couldn't be reported due
to, e.g., bugs in generating user data.
