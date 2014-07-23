module Devise
  module Strategies
    class Oauth2FacebookGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        Devise::Oauth2ProvidableFacebook.logger.debug("Facebook Grant Loaded")
        'facebook'
      end

      def authenticate_grant_type(client)
        Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Searching for user with facebook identifier:\"#{params[:uid]}\"")
        resource = mapping.to.find_for_authentication(:uid => params[:uid])

        # If the app could not be found
        if(!resource)
          Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Could not find user with facebook identifer:\"#{params[:uid]}\"")
          fb_user = Devise::Oauth2ProvidableFacebook.facebook_user_for_token(params[:facebook_access_token])
          if(fb_user && fb_user["email"])
             Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Falling back to email:\"#{fb_user["email"]}\"")
             resource = mapping.to.find_for_authentication(:email => fb_user["email"].to_s)
             if(resource)
               Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Found user with email:\"#{fb_user["email"]}\" saving facebook_idenfier: #{fb_user["id"]}")
               resource.uid = fb_user["id"].to_s
               resource.name = fb_user["name"].to_s
               resource.firstname = fb_user["first_name"].to_s
               resource.lastname = fb_user["last_name"].to_s
               resource.gender = fb_user["gender"].to_s
               resource.email = fb_user["email"].to_s
               resource.picture_url = fb_user["picture"]["data"]["url"].to_s
               resource.save
             end
           end
        end

        Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Validating access token for user with facebook identifier:\"#{params[:uid]}\"")
        if(resource)
          if(validate(resource) { resource.valid_facebook_access_token?(params[:facebook_access_token]) })
            Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Token is valid")
            success!(resource)
          elsif(!halted?)
            Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => Token is not valid")
            oauth_error! :invalid_grant, 'could not authenticate to facebook'
          end
        else
          Devise::Oauth2ProvidableFacebook.logger.debug("Oauth2FacebookGrantTypeStrategy => User not found")
          oauth_error! :invalid_grant, 'could not authenticate'
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_facebook_grantable, Devise::Strategies::Oauth2FacebookGrantTypeStrategy)
