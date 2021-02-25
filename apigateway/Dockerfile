FROM openjdk:8-jdk-alpine
LABEL maintainer="Gagan Dhand"
EXPOSE 8162
ADD ./target/apigateway-0.0.1-SNAPSHOT.jar /
ENTRYPOINT ["java","-jar","apigateway-0.0.1-SNAPSHOT.jar"]
