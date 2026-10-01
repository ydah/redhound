FROM ruby:3.4
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping tcpdump tshark dnsutils netcat-openbsd curl python3-scapy \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile redhound.gemspec ./
COPY lib/redhound/version.rb lib/redhound/version.rb
RUN bundle install
