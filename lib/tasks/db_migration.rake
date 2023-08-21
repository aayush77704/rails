namespace :db do
  desc "Run custom database migration script"
  task :migrate_new_version => :environment do
    class CreateNewTable < ActiveRecord::Migration[6.0]
    def change
        create_table :new_table do |t|
            t.string :name
            t.integer :age

            t.timestamps
        end
    end
  end
    puts "Running custom migration script..."
    # Example: ActiveRecord::Base.connection.execute("YOUR SQL HERE")
  end
end
