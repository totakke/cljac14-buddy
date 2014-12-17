(ns cljac.core.handler
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
            [buddy.auth.middleware :refer [wrap-access-rules
                                           wrap-authentication
                                           wrap-authorization]]
            [hiccup.core :refer [html]]))

(defn admin
  [req]
  (str "Logged in as " (name (get-in req [:session :identity]))))

(defn login-get
  [req]
  (html
   [:form {:method "post"}
    [:input {:type "text" :name "username"}]
    [:input {:type "password" :name "password"}]
    [:input {:type "hidden" :name "__anti-forgery-token" :value *anti-forgery-token*}]
    [:input {:type "submit"}]]))

(defn login-post
  [req]
  (let [username (get-in req [:form-params "username"])]
    (-> (redirect (get-in req [:query-params "next"] "/"))
      (assoc-in [:session :identity] (keyword username)))))

(defn logout
  []
  (-> (redirect "/login")
      (assoc :session {})))

(defroutes app-routes
  (GET "/" [] "Hello World")
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
