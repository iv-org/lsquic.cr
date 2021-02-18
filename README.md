# lsquic

Crystal bindings to the excellent [LSQUIC](https://github.com/litespeedtech/lsquic) library.

Releases track lsquic's versioning starting with `v2.18.1`.

`liblsquic.a` is licensed under `LICENSE.lsquic` and `LICENSE.chrome`.

Lsquic uses [boringssl](https://github.com/google/boringssl), which is licensed under `LICENSE.boringssl`.

This library is available under the MIT license.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     lsquic:
       github: iv-org/lsquic.cr
   ```

2. Run `shards install`

## Usage

```crystal
require "lsquic"

client = QUIC::Client.new("www.youtube.com")
client.get("/") # => #<HTTP::Client::Response>

client.get("/", headers: HTTP::Headers{
  "cookie" => "Some value",
  # ...
}) # => #<HTTP::Client::Response>

```

## Contributing

1. Fork it (<https://github.com/iv-org/lsquic.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Omar Roth](https://github.com/omarroth) - creator and maintainer
