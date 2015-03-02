(ns cljac14_buddy.core.handler
  (:require [compojure.core :refer :all]
            [compojure.handler :refer [site]]
            [compojure.route :as route]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.middleware.anti-forgery :refer [*anti-forgery-token*]]
            [ring.util.response :refer [redirect]]
            [ring.adapter.jetty :as jetty]
            [environ.core :refer [env]]
            [buddy.auth :refer [authenticated?]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication
                                           wrap-authorization]]
            [buddy.auth.accessrules :refer [wrap-access-rules]]
            [hiccup.core :refer [html]]
            [hiccup.page :refer :all]))

(defn- frame
  [& contents]
  (html5
   [:head
    [:meta {:name "viewport" :content "width=device-width, initial-scale=1"}]
    [:title "cljac14-buddy"]
    (include-css "//cdn.jsdelivr.net/pure/0.5.0/pure-min.css")
    (include-css "/css/main.css")]
   [:body
    [:div.wrapper
     contents]]))

(defn- index
  []
  (frame
   [:h1 "Welcome to buddy example"]
   [:a.pure-button {:href "/admin"} "To Secure Area"]))

(defn- admin
  [req]
  (frame
   [:h1 "Logged in as " [:strong (name (get-in req [:session :identity]))]]
   [:a.pure-button {:href "/"} "To Home"]
   (if (authenticated? req)
     [:a.pure-button.pure-button-primary {:href "/logout"} "Log out"])))

(defn login-get
  [req]
  (frame
   [:h1 "Log in"]
   [:form.pure-form {:method "post"}
    [:fieldset
     [:input {:type "text" :name "username" :placeholder "username"}]
     [:input {:type "password" :name "password" :placeholder "password"}]
     [:input {:type "hidden" :name "__anti-forgery-token" :value *anti-forgery-token*}]
     [:button.pure-button.pure-button-primary {:type "submit"} "Log in"]]]))

(defn login-post
  [req]
  (let [username (get-in req [:form-params "username"])]
    (-> (redirect (get-in req [:query-params "next"] "/"))
      (assoc-in [:session :identity] (keyword username)))))

(defn logout
  []
  (-> (redirect "/")
      (assoc :session {})))

(defroutes app-routes
  (GET "/" [] (index))
  (GET "/admin" req (admin req))
  (GET "/login" req (login-get req))
  (POST "/login" req (login-post req))
  (GET "/logout" [] (logout))
  (route/not-found "Not Found"))

(defn unauthorized-handler
  [req meta]
  (if (authenticated? req)
    (redirect "/")
    (redirect (format "/login?next=%s" (:uri req)))))

(def app
  (let [rules [{:pattern #"^/admin$" :handler authenticated?}]
        backend (session-backend {:unauthorized-handler unauthorized-handler})]
    (-> app-routes
        (wrap-access-rules {:rules rules :policy :allow})
        (wrap-authentication backend)
        (wrap-authorization backend)
        (wrap-defaults site-defaults))))

(defn -main [& [port]]
  (let [port (Integer. (or port (env :port) 5000))]
    (jetty/run-jetty (site #'app) {:port port :join? false})))
