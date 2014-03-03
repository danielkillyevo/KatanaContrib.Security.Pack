KatanaContrib.Security.Pack
=========================

##Introduction##

**[KatanaContrib.Security.Pack](http://www.nuget.org/packages/KatanaContrib.Security.Pack)** is a nuget package for adding all the KatanaContrib Authentication Providers to your project as a single pack. So you don't need to install each and every KatanaContrib Authentication packages one by one.
This simplifies the installation and the management of KatanaContrib packages by providing them as a single package.

##Problem##
ASP.NET MVC 5 has an inbuilt support for login with **Google, Facebook, Microsoft** and **Twitter**. But it still doesn't provide login with other major social networking sites such as **LinkedIn, Instagram, Github** etc. It was a huge drawback for the developers to concentrate on developing these additional login providers in their web applications. And the implementation of those login providers with different techniques, affected the code consistency and the performance of the web application.

##Solution##
As a solution to the above problem, we decided to implement the remaining login providers with MVC 5. So now the developers are only a single click away from adding these functionality to their web applications. At the moment we are ready with the following providers. This list will grow in near future.

 1. [Dropbox](http://www.nuget.org/packages/KatanaContrib.Security.Dropbox)
 2. [Foursquare](http://www.nuget.org/packages/KatanaContrib.Security.Foursquare)
 3. [Github](http://www.nuget.org/packages/KatanaContrib.Security.Github)
 4. [Instagram](http://www.nuget.org/packages/KatanaContrib.Security.Instagram)
 5. [LinkedIn](http://www.nuget.org/packages/KatanaContrib.Security.LinkedIn)
 6. [Meetup](http://www.nuget.org/packages/KatanaContrib.Security.Meetup)
 7. [StackExchange](http://www.nuget.org/packages/KatanaContrib.Security.StackExchange)

##Technology##
We have used **OAUTH 1.0a** and **OAUTH 2.0** for the implementation of these login providers with **Owin Katana**. Also we used the same code patterns used in the original implementation of the Katana Login Providers developed by Microsoft Katana team.

##How to Use##

In order to add it to your project or solution run the `Install-Package KatanaContrib.Security.Pack` command from the NuGet Package Manager console in Visual Studio. After this all the nuget packages of the implemented authentication middleware in KatanaContrib will be added to your project.

Following is a brief introduction to each of the providers included in the package.

####01. Dropbox####

KatanaContrib.Security.Dropbox will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the Dropbox authentication flow. The **KatanaContrib.Security.Dropbox** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use Dropbox authentication provider only without installing the full pack, you can just install **KatanaContrib.Security.Dropbox** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.Dropbox`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.Dropbox;`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseDropboxAuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `DropboxAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseDropboxAuthentication(new DropboxAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-Dropbox-Callback-Endpoint"),
                Caption = "My Dropbox",
        });


        //... custom code ...
}
```

####02. Foursquare####

KatanaContrib.Security.Foursquare will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the Foursquare authentication flow. The **KatanaContrib.Security.Foursquare** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use Foursquare authentication provider only without installing the full pack, you can just install **KatanaContrib.Security.Dropbox** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.Foursquare`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.Foursquare`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseFoursquareAuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `FoursquareAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseFoursquareAuthentication(new FoursquareAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-Foursquare-Callback-Endpoint"),
                Caption = "My Foursquare",
        });


        //... custom code ...
}
```

####03. Github####

KatanaContrib.Security.Github will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the Github authentication flow. The **KatanaContrib.Security.Github** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use Github authentication provider only, without installing the full pack, you can just install **KatanaContrib.Security.Github** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.Github`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.Github;`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseGithubAuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `GithubAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseGithubAuthentication(new GithubAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-Github-Callback-Endpoint"),
                Caption = "My Github,
        });


        //... custom code ...
}
```

####04. Instagram####

KatanaContrib.Security.Instagram will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the Instagram authentication flow. The **KatanaContrib.Security.Instagram** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use Instagram authentication provider only without installing the full pack, you can just install **KatanaContrib.Security.Instagram** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.Instagram`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.Instagram;`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseInstagramAuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `InstagramAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseInstagramAuthentication(new InstagramAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-Instagram-Callback-Endpoint"),
                Caption = "My Instagram",
        });


        //... custom code ...
}
```

####05. LinkedIn####

KatanaContrib.Security.LinkedIn will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the LinkedIn authentication flow. The **KatanaContrib.Security.LinkedIn** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use LinkedIn authentication provider only without installing the full pack, you can just install **KatanaContrib.Security.LinkedIn** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.LinkedIn`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.LinkedIn;`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseLinkedInAuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `LinkedInAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseLinkedInAuthentication(new LinkedInAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-LinkedIn-Callback-Endpoint"),
                Caption = "My LinkedIn",
        });


        //... custom code ...
}
```

####06. Meetup####

KatanaContrib.Security.Meetup will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the Meetup authentication flow. The **KatanaContrib.Security.Meetup** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use Meetup authentication provider only without installing the full pack, you can just install **KatanaContrib.Security.Meetup** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.Meetup`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.Meetup;`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseMeetupAuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `MeetupAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseMeetupAuthentication(new MeetupAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-Meetup-Callback-Endpoint"),
                Caption = "My Meetup",
        });


        //... custom code ...
}
```

####07. StackExchange####

KatanaContrib.Security.StackExchange will be included in the KatanaContrib.Security.Pack. It provides a Katana middleware that supports the StackExchange authentication flow. The **KatanaContrib.Security.StackExchange** was designed and implemented similar to **Microsoft.Owin.Security.Facebook** and **Microsoft.Owin.Security.Twitter**. This allows you to use it the same way as the security middlewares provided by Microsoft. 

If you intend to use StackExchange authentication provider only without installing the full pack, you can just install **KatanaContrib.Security.StackExchange** by running the following command in the Package Manager Console in Visual Studio.
`Install-Package KatanaContrib.Security.StackExchange`

A couple of actions will need to be done under the **App_Start** folder in the **Startup.Auth.cs** file :

 - Add namespace `using KatanaContrib.Security.StackExchange;`
 - In the `ConfigureAuth` call the corresponding *apps* extention method and pass your params:

```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseStackExchangeuthentication("YOUR_APP_KEY", "YOUR_APP_SECRET_KEY");

        //... custom code ...
}
```

 - If you need to pass more params application scope for instance pass a `StackExchangeAuthenticationOptions` object as param:
```csharp
public void ConfigureAuth(IAppBuilder app)
{
        //... custom code ..

        app.UseStackExchangeAuthentication(new StackExchangeAuthenticationOptions()
        {
                AppId = "YOUR_APP_API_KEY",
                AppSecret = "YOUR_APP_SECRET_KEY",
                CallbackPath = new PathString("/Your-StackExchange-Callback-Endpoint"),
                Caption = "My StackExchange",
        });


        //... custom code ...
}
```

Contribution
-------------
 - If you have something to contribute or you feel like contributing ping me here [@dkillewo](https://twitter.com/dkillewo)
 - If you implemented a Katana middleware or module add you feel it should be added to KatanaContrib ping me here [@dkillewo](https://twitter.com/dkillewo)

Got questions or suggestions? Feel free to create and issue or contact [@KatanaContrib](https://twitter.com/katanacontrib) / [@dkillewo](https://twitter.com/dkillewo) on twitter.
