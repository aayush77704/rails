# app/workers/my_worker.rb
class MyWorker
  include Sidekiq::Worker

  def perform(user_id, message)
    user = User.find(user_id)
    MyMailer.send_email(user, message).deliver_now
  end
end
