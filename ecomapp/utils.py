import six
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class MyPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        """
        This function returns a hash value by concatenating the string representation of a user's
        primary key and a timestamp.
        
        :param user: The "user" parameter is an instance of a Django user model, which represents a user
        of the application. It contains information such as the user's username, email, password, and
        other details
        :param timestamp: The timestamp parameter is a value representing a specific point in time,
        usually measured in seconds or milliseconds since a certain reference point (e.g. Unix epoch
        time). In this context, it is likely being used to generate a unique hash value for a user
        object, incorporating both the user's primary key (
        :return: A tuple containing the string representation of the user's primary key and the
        timestamp, both converted to text.
        """
        return (
            six.text_type(user.pk) + six.text_type(timestamp)
        )
    
password_reset_token = MyPasswordResetTokenGenerator()
