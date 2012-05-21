package play.modules.httpauthentication

import java.security.MessageDigest
import org.apache.commons.codec.binary.Base64.decodeBase64
import play.api.mvc._
import play.api._
import scala.util.parsing.combinator._


class HTTPAuthenticationPlugin(app: Application) extends Plugin

trait HTTPAuthentication {

  this: Controller =>

  import HTTPAuthentication._

  /**
   * Helper for authentication. Handle the get-header-then-try mechanism.
   */
  protected def authenticate[A](parser: Parser, opts: Map[String, String])
                               (check: Map[String,String] => Option[A])
                               (onSuccess: A => PlainResult)
                               (onFailure: Option[Map[String,String]] => String)
                               (implicit request: Request[Any]): PlainResult = {
    request.headers.get("Authorization").toRight(None).right flatMap { authHeader =>
      parser.parse(authHeader).toRight(None).right flatMap { a =>
        val auth = a + ("http-method" -> request.method)
        check(auth) toRight Some(auth)
      }
    } match {
    case Right(res) => onSuccess(res)
    case Left(auth) =>
      auth map { a =>
        play.api.Logger("application").debug("Bad authentication ("+a("username")+")")
      }
      val errorMsg = opts.get("errorMsg").getOrElse("Not authorized")
      Unauthorized(errorMsg).withHeaders("WWW-Authenticate" -> onFailure(auth))
    }
  }

  /**
   * Provides the Basic Authentication mechanism
   *
   * The password must be in clear text
   *
   * @param valid the list of valid username->password list
   */
  def BasicAuthentication(valid: Map[String, String], opts: Map[String, String])
                         (action: ((String, String)) => PlainResult)
                         (implicit request: Request[Any]): PlainResult =
  {
    BasicAuthentication(opts){ auth =>
      val u = auth("username")
      val p = auth("password")
      valid find { case (vu, vp) => vu == u && vp == vp }
    }(action)
  }

  def BasicAuthentication[A](opts: Map[String, String])
                            (check: Map[String, String] => Option[A])
                            (action: A => PlainResult)
                            (implicit request: Request[Any]): PlainResult =
  {
    authenticate(BasicParser, opts)(check)(action){ auth =>
      val realm = opts.get("realm").getOrElse("Secured")
      "Basic realm=\""+realm+"\""
    }
  }

  /**
   * Provides the Basic Authentication mechanism
   *
   * The password must be in clear text
   *
   * @param valid the list of valid username->password list
   */
  def DigestAuthentication(valid: Map[String, String], opts: Map[String, String] = Map())
                          (action: ((String, String)) => PlainResult)
                          (implicit request: Request[Any]): PlainResult =
  {
    authenticate(DigestParser, opts){ auth =>
      if (auth("nonce") == opts.get("nonce").getOrElse(genNonce)) {
        HTTPAuthentication.findDigestAuthentication(valid, auth)
      }
      else None
    }(action){ auth =>
      val nonce = opts.get("nonce").filterNot(_.isEmpty).getOrElse(genNonce)
      "Digest " + (
        Map(
          "realm" -> opts.get("realm").orElse(Some("Secured")),
          "domain" -> opts.get("domain"),
          "nonce" -> Some(nonce),
          "opaque" -> opts.get("opaque"),
          "stale" -> auth.map{ _("nonce") != nonce },
          "algorithm" -> opts.get("algorithm"),
          "qop" -> Some("auth")  // FIXME does not handle the qop=auth-int case
        ) collect { case (k, Some(v)) => k+"=\""+v+"\"" } mkString ", "
      )
    }
  }

}
object HTTPAuthentication {


  def findDigestAuthentication(valid: Map[String,String], args: Map[String, String]): Option[(String,String)] = {
    valid find { case (u,p) => checkDigestAuthentication(u, p, args) }
  }

  def checkDigestAuthentication(username: String, password: String, args: Map[String, String]): Boolean = {
    val username = args("username")
    val realm = args("realm")
    val nonce = args("nonce")
    val algorithm = args.get("algorithm").getOrElse("MD5")
    val opaque = args.get("opaque")
    val uri = args("uri")
    val clientResponse = args("response")
    val qop = args.get("qop")
    val cnonce = args.get("cnonce")
    val nc = args("nc")
    val httpMethod = args("http-method")

    val algo = MessageDigest.getInstance(algorithm)
    def H(data: String): String = digestToHex(algo.digest(data.getBytes))
    def KD(secret: String, data: String): String = H(secret+":"+data)

    val A1 = algorithm match {
      case "MD5-sess" => H(username+":"+realm+":"+password)+":"+nonce+":"+cnonce
      case _ => username+":"+realm+":"+password
    }

    // FIXME does not handle the qop=auth-int case
    val A2 = httpMethod+":"+uri

    val response = qop match {
      case Some(q) => KD(H(A1), nonce+":"+nc+":"+cnonce.get+":"+q+":"+H(A2))
      case None => KD(H(A1), nonce+":"+H(A2))
    }

    response == clientResponse
  }

  def genNonce(implicit request: Request[Any]): String = {
    import java.util.Calendar
    val md5 = MessageDigest.getInstance("MD5")
    val date = Calendar.getInstance.get(Calendar.DAY_OF_YEAR)
    val toDigest = request.domain + ":" + date
    digestToHex(md5.digest(toDigest.getBytes))
  }

  def digestToHex(bytes: Array[Byte]): String =
    bytes.map(0xFF & _).map { "%02x".format(_) }.foldLeft(""){_ + _}


  // Authentication's headers parsers


  trait Parser {
    def parse(str: String): Option[Map[String,String]]
  }

  object BasicParser extends RegexParsers with Parser {

    def value: Parser[String] = ".+".r
    def username: Parser[String] = "[^:]+".r
    def password: Parser[String] = ".+".r

    def basic: Parser[String] = "(?i)Basic".r ~> value
    def basicDecoded: Parser[(String,String)] = username ~ ":" ~ password ^^ { case u ~ _ ~ p => (u, p) }

    def parse(encoded: String): Option[Map[String, String]] = {
      parseAll(basic, encoded) match {
        case Success(res, _) =>
          val decoded = new String(decodeBase64(res.getBytes))
          parseAll(basicDecoded, decoded) match {
            case Success((u, p), _) => Some(Map("username" -> u, "password" -> p))
            case e =>
              play.api.Logger("application").debug(e.toString)
              None
          }
        case e =>
          play.api.Logger("application").debug(e.toString)
          None
      }
    }

  }

  object DigestParser extends RegexParsers with Parser {
    override val skipWhitespace = false

    def SPACES: Parser[String] = "[\t ]+".r
    def quoted: Parser[String] = "\"" ~> "[^\"]+".r <~ "\""
    def unquoted: Parser[String] = "[^,]+".r
    def key: Parser[String] = """([^="]+)""".r
    def value: Parser[String] = quoted | unquoted
    def keyvalue: Parser[(String,String)] = (SPACES?) ~> key ~ "=" ~ value <~ (SPACES?) ^^ { case k ~ _ ~ v => (k, v) }

    def digest: Parser[Map[String, String]] = "(?i)Digest".r ~> SPACES ~> repsep(keyvalue, "," ~ (SPACES?)) ^^ (_.toMap)

    def parse(s: String): Option[Map[String, String]] = {
      parseAll(digest, s) match {
        case Success(res, _) => Some(res)
        case e =>
          play.api.Logger("application").debug(e.toString)
          None
      }
    }
  }

}
