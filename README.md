# Redhound [![Gem Version](https://badge.fury.io/rb/redhound.svg)](https://badge.fury.io/rb/redhound) [![Test](https://github.com/ydah/redhound/actions/workflows/main.yml/badge.svg)](https://github.com/ydah/redhound/actions/workflows/main.yml)

Pure Ruby packet analyzer.
At this time, it is only guaranteed to work on Linux.

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add redhound
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install redhound
```

## Usage

```command
   ___         ____                     __
  / _ \___ ___/ / /  ___  __ _____  ___/ /
 / , _/ -_) _  / _ \/ _ \/ // / _ \/ _  /
/_/|_|\__/\_,_/_//_/\___/\_,_/_//_/\_,_/

Version: 1.0.1
Dump and analyze network packets.

Usage: redhound [options] ...

Options:
    -i, --interface INTERFACE        name or idx of interface
    -D, --list-interfaces            print list of interfaces and exit
    -w FILE                          write packets to a pcap capture file format to file
    -h, --help                       display this help and exit
    -v, --version                    display version information and exit
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ydah/redhound. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/ydah/redhound/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Redhound project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/ydah/redhound/blob/main/CODE_OF_CONDUCT.md).
