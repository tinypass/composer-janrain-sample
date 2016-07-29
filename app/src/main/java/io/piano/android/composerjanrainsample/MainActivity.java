package io.piano.android.composerjanrainsample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Toast;

import com.janrain.android.Jump;

import io.piano.android.composer.Composer;
import io.piano.android.composer.ExperienceExecuteListener;
import io.piano.android.composer.ShowLoginListener;
import io.piano.android.composer.model.ExperienceExecute;
import io.piano.android.composer.model.ShowLogin;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.button_composer).setOnClickListener(EXECUTE_COMPOSER);
    }

    @Override
    protected void onPause() {
        super.onPause();
        Jump.saveToDisk(this);
    }

    private final View.OnClickListener EXECUTE_COMPOSER = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            new Composer(MainActivity.this, BuildConfig.PIANO_AID, true)
                    .user(Jump.getSignedInUser() == null ? null : Jump.getAccessToken(), "janrain")
                    .addListener(SHOW_LOGIN_LISTENER)
                    .addListener(EXPERIENCE_EXECUTE_LISTENER)
                    .execute();
        }
    };

    private final ShowLoginListener SHOW_LOGIN_LISTENER = new ShowLoginListener() {
        @Override
        public void onExecuted(ShowLogin event) {
            Jump.showSignInDialog(MainActivity.this, null, SIGN_IN_RESULT_HANDLER, null);
        }
    };

    private final Jump.SignInResultHandler SIGN_IN_RESULT_HANDLER = new Jump.SignInResultHandler() {
        @Override
        public void onSuccess() {
            Toast.makeText(MainActivity.this, "user = " + Jump.getSignedInUser(), Toast.LENGTH_LONG).show();
        }

        @Override
        public void onFailure(SignInError error) {
            Toast.makeText(MainActivity.this, error.toString(), Toast.LENGTH_LONG).show();
        }
    };

    private final ExperienceExecuteListener EXPERIENCE_EXECUTE_LISTENER = new ExperienceExecuteListener() {
        @Override
        public void onExecuted(ExperienceExecute event) {
            Toast.makeText(MainActivity.this, "user's uid = " + event.user.uid, Toast.LENGTH_SHORT).show();
        }
    };
}
