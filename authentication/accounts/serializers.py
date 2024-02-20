from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
User = get_user_model()
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'profile_pic','first_name','last_name',"avatar_url")
        extra_kwargs = {'password': {'write_only': True}}

   
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create_user(
            email=validated_data['email'],
            # name=validated_data['name'],
            username=validated_data['email'],
            profile_pic=validated_data.get('profile_pic'),
            first_name = validated_data.get('first_name'),
            last_name = validated_data.get('last_name'),
            avatar_url = validated_data.get('avatar_url'),
        )
        if password:
            user.set_password(password)
            user.save()
        return user
class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'profile_pic', 'first_name', 'last_name', 'avatar_url')
        read_only_fields = ('email',)

    def update(self, instance, validated_data):
        profile_pic = validated_data.get('profile_pic')
        avatar_url = validated_data.get('avatar_url')

        
        if profile_pic:
            if instance.profile_pic:
                default_storage.delete(instance.profile_pic.name)
            instance.profile_pic = profile_pic

        
        if avatar_url:
            instance.avatar_url = avatar_url

        return super().update(instance, validated_data)
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, style={'input_type': 'password'})