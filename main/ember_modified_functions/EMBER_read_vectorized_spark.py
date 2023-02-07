def read_vectorized_spark(data_dir, subset=None, feature_version=2):
    
    if subset is not None and subset not in ["train", "test"]:
        return None

    extractor = PEFeatureExtractor(feature_version)
    ndim = extractor.dim
    X_train = None
    y_train = None
    X_test = None
    y_test = None

    if subset is None or subset == "train":
        X_train_path = os.path.join(data_dir, "X_train.dat")
        y_train_path = os.path.join(data_dir, "y_train.dat")
        y_train = np.memmap(y_train_path, dtype=np.float32, mode="r")
        N = y_train.shape[0]
        X_train = np.memmap(X_train_path, dtype=np.float32, mode="r", shape=(N, ndim))
        spark_train = []
        i=0
        for row in X_train:
            spark_train.append( (DenseVector(X_train[i].tolist()), y_train[i].tolist()) )
            i+=1
        
        if subset == "train":
            return spark_train

    if subset is None or subset == "test":
        X_test_path = os.path.join(data_dir, "X_test.dat")
        y_test_path = os.path.join(data_dir, "y_test.dat")
        y_test = np.memmap(y_test_path, dtype=np.float32, mode="r")
        N = y_test.shape[0]
        X_test = np.memmap(X_test_path, dtype=np.float32, mode="r", shape=(N, ndim))
        spark_test = []
        i=0
        for row in X_test:
            spark_test.append( (DenseVector(X_test[i].tolist()), y_test[i].tolist()) )
            i+=1
        
        if subset == "test":
            return spark_test

    return spark_train, spark_test