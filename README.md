HTTP Authentication
===================

This Play 2 plugin provide helpers for HTTP Authentication.

Basic Authentication
--------------------

There are 2 ways to use Basic Authentication:
* Providing the list of username->password pairs (both in plain-text).
* Providing an check function which will be called with the given informations.

Digest Authentication
--------------------

The Digest Authentication allows to check if 2 passwords are equals, but it need the plain-text password (by design).
Thus this helper can only be called with a username->password list.

Setting up with sbt
-------------------

Configure a new resolver:

~~~scala
resolvers += "HTTP Authentication" at "http://dohzya.github.com/play2-plugin-httpauthentication/"
~~~

Add the library dependency:

~~~scala
libraryDependencies +="play.modules.httpauthentication" %% "play-2.0-http-authentication-plugin" % "0.1-SNAPSHOT",
~~~

Example
-------

~~~scala
import play.modules.httpauthentication.HTTPAuthentication

object BackOffice extends Controller with HTTPAuthentication {

  /**
   * Invokes the authentication procedure.
   *
   * It provides the valid user object to the given action, instead of a Map.
   */
  def Authenticate(action: User => Result)(implicit request: Request[Any]): Result = {
    BasicAuthentication(Map("realm" -> "Back Office")){ auth =>
      User.findAndCheck(auth("username"), auth("password"))
    }(action)
  }

  def index = Action { implicit request =>
    Authenticate { implicit user =>
      Ok(html.admin.index())
    }
  }

  def logs = Action { implicit request =>
    Authenticate { implicit user =>
      Ok(html.admin.logs())
    }
  }

}
~~~
