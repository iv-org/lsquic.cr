require "./spec_helper"

describe QUIC do
  it "works" do
    client = QUIC::Client.new("www.youtube.com")

    5.times do
      client.get("/").status_code.should eq(200)
    end

    client.close
  end

  it "works with fibers" do
    ch = Channel(Int32).new

    5.times do
      spawn do
        client = QUIC::Client.new("www.youtube.com")

        5.times do
          ch.send client.get("/").status_code
        end

        client.close
      end
    end

    (5 * 5).times do
      ch.receive.should eq(200)
    end
  end

  it "restarts engine after closing" do
    client = QUIC::Client.new("www.youtube.com")

    client.get("/").status_code.should eq(200)
    client.close
    Fiber.yield
    client.get("/").status_code.should eq(200)
  end
end
