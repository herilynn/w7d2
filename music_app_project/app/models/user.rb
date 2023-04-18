class User < ApplicationRecord
  validates :email, presence: true, uniqueness: true
    
  validates :password_digest, presence: true
  
  validates :session_token, presence: true, uniqueness: true

  before_validation :ensure_session_token

  #SPIRE

  attr_reader :password

  def self.find_by_credentials(email, password)            #finding the user in the database - only used when we login

      user = User.find_by(username: username)

      if user && user.is_password(password)
          return user 

      else 
          return nil 

      end 

  end 

  def password=(password)            #setter for password 
                                      #when we login, we want to salt a password, hash it sand save it

      self.password_digest = BCrypt::Password.create(password)
      @password = password              #do this so that when we call User.save in create we can access the instance variable      

  end 


  def is_password?(password)           #logic  that checks if an inputted password matches the DB

      password_object = BCrypt::Password.new(self.password_digest)

      password_object.is_password?(password)

  end 


  def reset_session_token!            #

      self.reset_session_token = SecureRandom::urlsafe_basic64
      self.save! #mutates vs. not mutates without the !
      self.session_token              #updtas the session cookies for the current user

  end 

  private 

  def ensure_session_token
    self.session_token ||= SecureRandom::urlsafe_basic64
  end 

  def generate_session_token!

      self.generate_session_token = SecureRandom::urlsafe_basic64
      self.save! 
      self.session_token

  end 
end