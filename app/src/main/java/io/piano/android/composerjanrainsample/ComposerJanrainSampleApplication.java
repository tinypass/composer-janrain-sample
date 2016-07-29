package io.piano.android.composerjanrainsample;

import android.app.Application;

import com.janrain.android.Jump;
import com.janrain.android.JumpConfig;

public class ComposerJanrainSampleApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        initJump();
    }

    private void initJump() {
        JumpConfig jumpConfig = new JumpConfig();
        jumpConfig.engageAppId = BuildConfig.JANRAIN_ENGAGE_APP_ID;
        jumpConfig.captureAppId = BuildConfig.JANRAIN_CAPTURE_APP_ID;
        jumpConfig.captureDomain = BuildConfig.JANRAIN_CAPTURE_DOMAIN;
        jumpConfig.captureClientId = BuildConfig.JANRAIN_CAPTURE_CLIENT_ID;
        jumpConfig.captureFlowName = BuildConfig.JANRAIN_CAPTURE_FLOW_NAME;
        jumpConfig.captureTraditionalSignInFormName = BuildConfig.JANRAIN_CAPTURE_TRADITIONAL_SIGN_IN_FORM_NAME;
        jumpConfig.captureLocale = BuildConfig.JANRAIN_CAPTURE_LOCALE;
        jumpConfig.traditionalSignInType = Jump.TraditionalSignInType.valueOf(BuildConfig.JANRAIN_TRADITIONAL_SIGN_IN_TYPE);
        Jump.init(this, jumpConfig);
    }
}
