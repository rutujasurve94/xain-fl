import tensorflow as tf
from tensorflow.keras.layers import Conv2D, Dense, Dropout, Flatten, Input, MaxPool2D


def fc_compiled(input_shape=(28, 28, 1), num_classes=10) -> tf.keras.Model:
    inputs = Input(shape=input_shape)
    x = Flatten()(inputs)
    x = Dense(128, activation="relu")(x)
    outputs = Dense(num_classes, activation="softmax")(x)

    model = tf.keras.Model(inputs=inputs, outputs=outputs)

    model.compile(
        loss=tf.keras.losses.categorical_crossentropy,
        optimizer=tf.keras.optimizers.Adam(),
        metrics=["accuracy"],
    )
    return model


def cnn_compiled(input_shape=(28, 28, 1), num_classes=10) -> tf.keras.Model:
    inputs = Input(shape=input_shape)
    x = Conv2D(32, kernel_size=3, activation="relu")(inputs)
    x = Conv2D(64, kernel_size=3, activation="relu")(x)
    x = MaxPool2D(pool_size=(2, 2))(x)
    x = Dropout(0.25)(x)
    x = Flatten()(x)
    x = Dense(128, activation="relu")(x)
    x = Dropout(0.5)(x)
    outputs = Dense(num_classes, activation="softmax")(x)

    model = tf.keras.Model(inputs=inputs, outputs=outputs)

    model.compile(
        loss=tf.keras.losses.categorical_crossentropy,
        optimizer=tf.keras.optimizers.Adam(),
        metrics=["accuracy"],
    )
    return model
