package com.rebootorz.vuleye;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class VulEyeApp extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(VulEyeApp.class.getResource("vuleye.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 830, 630);
        stage.setScene(scene);
        stage.setMinWidth(890);
        stage.setMinHeight(630);
        stage.setMaxWidth(890);
        stage.setMaxHeight(630);
        stage.setTitle("VulEye");
        stage.setScene(scene);
        stage.show();


    }

    public static void main(String[] args) {
        launch();
    }
}