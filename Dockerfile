# Step 1: Use an official Ruby runtime as a parent image
FROM ruby:3.2.1

# Step 2: Set the working directory in the container
WORKDIR /app

# Step 3: Install system dependencies
RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs

# Step 4: Install Bundler
RUN gem install bundler

# Step 5: Copy the Gemfile and Gemfile.lock into the container
COPY Gemfile Gemfile.lock ./

# Step 6: Install RubyGems dependencies
RUN bundle install

# Step 7: Copy the rest of the application code into the container
COPY . .

# Step 8: Expose a port for your Rails application (e.g., 3000)
EXPOSE 3000

# Step 9: Start your Rails application server
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]
