# frozen_string_literal: true

# Helper module for loading fixture files in RSpec tests.
# To use:
# 1. Place this file in `spec/support/file_fixtures.rb`.
# 2. Ensure `spec/support` is required in `rails_helper.rb` or `spec_helper.rb`:
#    Dir[Rails.root.join('spec', 'support', '**', '*.rb')].sort.each { |f| require f }
# 3. Include it in your spec files: `include FileFixtures`
# 4. Create a `spec/fixtures/files` directory to store your fixture files.
#    Example: `spec/fixtures/files/my_data.json`
# 5. Use in tests: `data = file_fixture('my_data.json').read` or `parsed_data = JSON.parse(file_fixture('my_data.json').read)`

module FileFixtures
  FIXTURE_PATH = Rails.root.join('spec', 'fixtures', 'files')

  # Returns a Pathname object to the fixture file.
  #
  # @param fixture_name [String] The name of the fixture file (e.g., 'user_data.json').
  # @return [Pathname] Pathname object to the fixture file.
  # @raise [ArgumentError] if the fixture file does not exist.
  def file_fixture(fixture_name)
    path = Pathname.new(File.join(FIXTURE_PATH, fixture_name))

    if path.exist?
      path
    else
      msg = "the fixture '#{path}' does not exist."
      # You might want to display a list of available fixtures here for easier debugging.
      # available_fixtures = Dir.glob(File.join(FIXTURE_PATH, '*')).map { |f| File.basename(f) }
      # msg += "\nAvailable fixtures: #{available_fixtures.join(', ')}"
      raise ArgumentError, msg
    end
  end

  # Helper to directly read and parse a JSON fixture file.
  #
  # @param fixture_name [String] The name of the JSON fixture file.
  # @param symbolize_names [Boolean] Whether to symbolize keys in the parsed JSON.
  # @return [Hash, Array] The parsed JSON data.
  def json_fixture(fixture_name, symbolize_names: true)
    JSON.parse(file_fixture(fixture_name).read, symbolize_names: symbolize_names)
  end

  # Helper to directly read and parse a YAML fixture file.
  #
  # @param fixture_name [String] The name of the YAML fixture file.
  # @param permitted_classes [Array<Class>] Permitted classes for YAML.safe_load.
  # @param aliases [Boolean] Aliases for YAML.safe_load
  # @return [Object] The parsed YAML data.
  def yaml_fixture(fixture_name, permitted_classes: [Symbol], aliases: true)
    YAML.safe_load(file_fixture(fixture_name).read, permitted_classes: permitted_classes, aliases: aliases)
  end
end

# Configure RSpec to include this module in all spec types or specific ones.
# In `rails_helper.rb` or `spec_helper.rb`:
# RSpec.configure do |config|
#   config.include FileFixtures
# end
