FROM ruby:3.3.4
RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs iputils-ping iproute2 iptables
WORKDIR /app
COPY Gemfile /app/Gemfile
RUN bundle install
ENV LANG=ja_JP.UTF-8
ENV TZ=Asia/Tokyo
