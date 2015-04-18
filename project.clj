(defproject cljac14-buddy "0.1.0-SNAPSHOT"
  :description "An example web application for buddy"
  :url "https://cljac14-buddy.herokuapp.com"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [compojure "1.3.1"]
                 [ring/ring-jetty-adapter "1.2.2"]
                 [ring/ring-defaults "0.1.2"]
                 [environ "0.5.0"]
                 [buddy "0.5.1"]
                 [hiccup "1.0.5"]]
  :plugins [[lein-ring "0.8.13"]
            [environ/environ.lein "0.2.1"]]
  :hooks [environ.leiningen.hooks]
  :uberjar-name "cljac14-buddy.jar"
  :ring {:handler cljac14_buddy.core.handler/app}
  :profiles {:dev {:dependencies [[javax.servlet/servlet-api "2.5"]
                                  [ring-mock "0.1.5"]]}
             :production {:env {:production true}}})
